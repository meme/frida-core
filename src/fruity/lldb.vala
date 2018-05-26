namespace Frida.Fruity {
	public class LLDBClient : Object, AsyncInitable {
		public LockdownClient lockdown {
			get;
			construct;
		}

		private IOStream stream;
		private DataInputStream input;
		private OutputStream output;
		private Cancellable cancellable = new Cancellable ();

		private State state = STOPPED;
		private AckMode ack_mode = SEND_ACKS;
		private Gee.ArrayQueue<Bytes> pending_writes = new Gee.ArrayQueue<Bytes> ();
		private Gee.ArrayQueue<PendingResponse> pending_responses = new Gee.ArrayQueue<PendingResponse> ();

		private enum State {
			STOPPED,
			RUNNING,
			STOPPING
		}

		private enum AckMode {
			SEND_ACKS,
			SKIP_ACKS
		}

		private enum ChecksumType {
			PROPER,
			ZEROED
		}

		private const string ACK_NOTIFICATION = "+";
		private const string NACK_NOTIFICATION = "-";
		private const string PACKET_MARKER = "$";
		private const char PACKET_CHARACTER = '$';
		private const string CHECKSUM_MARKER = "#";
		private const char CHECKSUM_CHARACTER = '#';
		private const char ESCAPE_CHARACTER = '}';
		private const uint8 ESCAPE_KEY = 0x20;
		private const char REPEAT_CHARACTER = '*';
		private const uint8 REPEAT_BASE = 0x20;
		private const uint8 REPEAT_BIAS = 3;

		private LLDBClient (LockdownClient lockdown) {
			Object (lockdown: lockdown);
		}

		public static async LLDBClient open (LockdownClient lockdown, Cancellable? cancellable = null) throws LLDBError {
			var client = new LLDBClient (lockdown);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				assert (e is LLDBError);
				throw (LLDBError) e;
			}

			return client;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws LLDBError {
			try {
				stream = yield lockdown.start_service ("com.apple.debugserver");
				input = new DataInputStream (stream.get_input_stream ());
				output = stream.get_output_stream ();

				process_incoming_packets.begin ();
				write_string (ACK_NOTIFICATION);

				yield request ("QStartNoAckMode");
				ack_mode = SKIP_ACKS;

				yield request ("QThreadSuffixSupported");
				yield request ("QListThreadsInStopReply");
				yield request ("QSetDetachOnError:0");
			} catch (LockdownError e) {
				if (e is LockdownError.INVALID_SERVICE)
					throw new LLDBError.DDI_NOT_MOUNTED ("Developer Disk Image not mounted");
				else
					throw new LLDBError.FAILED ("%s", e.message);
			}

			return true;
		}

		public async void close () {
			cancellable.cancel ();

			var source = new IdleSource ();
			source.set_callback (() => {
				close.callback ();
				return false;
			});
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield stream.close_async ();
			} catch (IOError e) {
			}
		}

		public async ProcessInfo launch (string[] argv, LaunchOptions? options = null) throws LLDBError {
			if (options != null) {
				foreach (var env in options.env)
					yield request ("QEnvironment:" + env);

				var arch = options.arch;
				if (arch != null)
					yield request ("QLaunchArch:" + arch);

				if (options.aslr == DISABLE)
					yield request ("QSetDisableASLR:1");
			}

			var set_args_request = new StringBuilder ("A");
			int arg_index = 0;
			foreach (var arg in argv) {
				if (arg_index > 0)
					set_args_request.append_c (',');

				var length = arg.length;
				var hex_length = length * 2;
				set_args_request.append_printf ("%u,%u,", hex_length, arg_index);

				for (int byte_index = 0; byte_index != length; byte_index++)
					set_args_request.append_printf ("%02x", arg[byte_index]);

				arg_index++;
			}
			yield request (set_args_request.str);

			yield request ("qLaunchSuccess");

			return yield get_process_info ();
		}

		private async ProcessInfo get_process_info () throws LLDBError {
			var response = yield request ("qProcessInfo");

			var raw_info = PropertyDictionary.parse (response.payload);

			var info = new ProcessInfo ();
			info.pid = raw_info.get_uint ("pid");
			info.parent_pid = raw_info.get_uint ("parent-pid");
			info.real_uid = raw_info.get_uint ("real-uid");
			info.real_gid = raw_info.get_uint ("real-gid");
			info.effective_uid = raw_info.get_uint ("effective-uid");
			info.effective_gid = raw_info.get_uint ("effective-gid");
			info.cpu_type = raw_info.get_uint ("cputype");
			info.cpu_subtype = raw_info.get_uint ("cpusubtype");
			info.pointer_size = raw_info.get_uint ("ptrsize");
			info.os_type = raw_info.get_string ("ostype");
			info.vendor = raw_info.get_string ("vendor");
			info.byte_order = (raw_info.get_string ("endian") == "little") ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;

			return info;
		}

		private async Packet request (string payload) throws LLDBError {
			var pending = new PendingResponse (() => request.callback ());
			pending_responses.offer_tail (pending);
			write_packet (payload);
			yield;

			var response = pending.response;
			if (response == null)
				throw pending.error;

			return response;
		}

		private async void process_incoming_packets () {
			while (true) {
				try {
					var packet = yield read_packet ();
					dispatch_packet (packet);
				} catch (LLDBError error) {
					foreach (var pending_response in pending_responses)
						pending_response.complete_with_error (error);
					pending_responses.clear ();
					return;
				}
			}
		}

		private async void process_pending_writes () {
			while (!pending_writes.is_empty) {
				Bytes current = pending_writes.peek_head ();

				size_t bytes_written;
				try {
					yield output.write_all_async (current.get_data (), Priority.DEFAULT, cancellable, out bytes_written);
				} catch (GLib.Error e) {
					return;
				}

				pending_writes.poll_head ();
			}
		}

		private void dispatch_packet (Packet packet) throws LLDBError {
			switch (state) {
				case STOPPED:
					handle_response (packet);
					break;
				case RUNNING:
				case STOPPING:
					handle_notification (packet);
					break;
				default:
					assert_not_reached ();
			}
		}

		private void handle_response (Packet response) throws LLDBError {
			var pending = pending_responses.poll_head ();
			if (pending == null)
				throw new LLDBError.PROTOCOL ("Unexpected response");

			var payload = response.payload;
			if (payload.length == 3 && payload[0] == 'E') {
				pending.complete_with_error (new LLDBError.FAILED ("Request failed: %s", payload[1:3]));
			} else {
				pending.complete_with_response (response);
			}
		}

		private void handle_notification (Packet packet) throws LLDBError {
		}

		private async Packet read_packet () throws LLDBError {
			string first = yield read_string (1);
			if (first == ACK_NOTIFICATION || first == NACK_NOTIFICATION)
				return yield read_packet ();

			string rest;
			try {
				size_t rest_length;
				rest = yield input.read_upto_async (CHECKSUM_MARKER, 1, Priority.DEFAULT, cancellable, out rest_length);
				if (rest_length == 0)
					rest = "";
			} catch (IOError e) {
				throw new LLDBError.CONNECTION_CLOSED ("%s", e.message);
			}

			string trailer = yield read_string (3);

			var packet = depacketize (first.concat (rest, trailer));

			if (ack_mode == SEND_ACKS)
				write_string (ACK_NOTIFICATION);

			return packet;
		}

		private void write_packet (string payload) {
			var checksum_type = (ack_mode == SEND_ACKS) ? ChecksumType.PROPER : ChecksumType.ZEROED;
			write_bytes (packetize (payload, checksum_type));
		}

		private async string read_string (uint length) throws LLDBError {
			var buf = new uint8[length + 1];
			buf[length] = 0;

			ssize_t n;
			try {
				n = yield input.read_async (buf[0:length], Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw new LLDBError.CONNECTION_CLOSED ("%s", e.message);
			}

			if (n == 0)
				throw new LLDBError.CONNECTION_CLOSED ("Connection closed");

			return (string) buf;
		}

		private void write_string (string str) {
			unowned uint8[] buf = (uint8[]) str;
			write_bytes (new Bytes (buf[0:str.length]));
		}

		private void write_bytes (Bytes bytes) {
			pending_writes.offer_tail (bytes);
			if (pending_writes.size == 1)
				process_pending_writes.begin ();
		}

		private static Bytes packetize (string payload, ChecksumType checksum_type) {
			var result = new StringBuilder.sized (1 + payload.length + 1 + 2);

			result.append_c (PACKET_CHARACTER);

			var length = payload.length;
			for (int i = 0; i != length; i++) {
				char ch = payload[i];
				switch (ch) {
					case PACKET_CHARACTER:
					case CHECKSUM_CHARACTER:
					case ESCAPE_CHARACTER:
					case REPEAT_CHARACTER:
						result.append_c (ESCAPE_CHARACTER);
						result.append_c ((char) ((uint8) ch ^ ESCAPE_KEY));
						break;
					default:
						result.append_c (ch);
						break;
				}
			}

			result.append_c (CHECKSUM_CHARACTER);

			if (checksum_type == PROPER) {
				result.append_printf ("%02x", compute_checksum (result.str[1:1 + length]));
			} else {
				result.append ("00");
			}

			return StringBuilder.free_to_bytes ((owned) result);
		}

		private static Packet depacketize (string data) throws LLDBError {
			var length = data.length;
			var result = new StringBuilder.sized (length);

			for (int offset = 1; offset < length - 3; offset++) {
				char ch = data[offset];
				if (ch == ESCAPE_CHARACTER) {
					uint8 escaped_byte = data[++offset];
					result.append_c ((char) (escaped_byte ^ ESCAPE_KEY));
				} else if (ch == REPEAT_CHARACTER) {
					if (offset == 0)
						throw new LLDBError.PROTOCOL ("Invalid packet");
					char char_to_repeat = data[offset - 1];
					uint8 repeat_count = (uint8) data[++offset] - REPEAT_BASE + REPEAT_BIAS;
					for (uint8 repeat_index = 0; repeat_index != repeat_count; repeat_index++)
						result.append_c (char_to_repeat);
				} else {
					result.append_c (ch);
				}
			}

			return new Packet.from_bytes (StringBuilder.free_to_bytes ((owned) result));
		}

		private static uint8 compute_checksum (string data) {
			uint8 sum = 0;

			var length = data.length;
			for (int i = 0; i != length; i++)
				sum += (uint8) data[i];

			return sum;
		}

		private class Packet {
			public string payload {
				get;
				private set;
			}

			private Bytes payload_bytes;

			public Packet.from_bytes (Bytes payload_bytes) {
				this.payload_bytes = payload_bytes;
				this.payload = (string) payload_bytes.get_data ();
			}
		}

		private class PendingResponse {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public Packet? response {
				get;
				private set;
			}

			public LLDBError? error {
				get;
				private set;
			}

			public PendingResponse (owned CompletionHandler handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_response (Packet? response) {
				this.response = response;
				handler ();
			}

			public void complete_with_error (LLDBError? error) {
				this.error = error;
				handler ();
			}
		}

		private class PropertyDictionary {
			private Gee.HashMap<string, string> properties = new Gee.HashMap<string, string> ();

			public static PropertyDictionary parse (string raw_properties) throws LLDBError {
				var dictionary = new PropertyDictionary ();

				var properties = dictionary.properties;

				var pairs = raw_properties.split (";");
				foreach (var pair in pairs) {
					if (pair.length == 0)
						continue;

					var tokens = pair.split (":", 2);
					if (tokens.length != 2)
						throw new LLDBError.PROTOCOL ("Invalid property dictionary pair");
					var key = tokens[0];
					var val = tokens[1];

					properties[key] = val;
				}

				return dictionary;
			}

			public uint get_uint (string name) throws LLDBError {
				var raw_val = get_string (name);

				uint64 val;
				try {
					uint64.from_string (raw_val, out val, 16, uint.MIN, uint.MAX);
				} catch (NumberParserError e) {
					throw new LLDBError.PROTOCOL ("Property '%s' is not a valid uint: %s", name, e.message);
				}

				return (uint) val;
			}

			public string get_string (string name) throws LLDBError {
				var val = properties[name];
				if (val == null)
					throw new LLDBError.PROTOCOL ("Property '%s' not found", name);
				return val;
			}
		}
	}

	public errordomain LLDBError {
		FAILED,
		CONNECTION_CLOSED,
		DDI_NOT_MOUNTED,
		PROTOCOL
	}

	public class LaunchOptions : Object {
		public string[] env {
			get;
			set;
			default = {};
		}

		public string? arch {
			get;
			set;
		}

		public Aslr aslr {
			get;
			set;
			default = AUTO;
		}
	}

	public class ProcessInfo : Object {
		public uint pid {
			get;
			set;
		}

		public uint parent_pid {
			get;
			set;
		}

		public uint real_uid {
			get;
			set;
		}

		public uint real_gid {
			get;
			set;
		}

		public uint effective_uid {
			get;
			set;
		}

		public uint effective_gid {
			get;
			set;
		}

		public uint cpu_type {
			get;
			set;
		}

		public uint cpu_subtype {
			get;
			set;
		}

		public uint pointer_size {
			get;
			set;
		}

		public string os_type {
			get;
			set;
		}

		public string vendor {
			get;
			set;
		}

		public ByteOrder byte_order {
			get;
			set;
		}
	}

	public enum Aslr {
		AUTO,
		DISABLE
	}
}
