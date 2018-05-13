namespace Frida.Fruity {
	public class Client : Object {
		public SocketConnection connection {
			get;
			private set;
		}
		private InputStream input;
		private Cancellable input_cancellable = new Cancellable ();
		private OutputStream output;
		private Cancellable output_cancellable = new Cancellable ();

		private bool is_processing_messages;
		private uint last_tag;
		private uint mode_switch_tag;
		private Gee.ArrayList<PendingResponse> pending_responses;

		private const uint16 USBMUX_SERVER_PORT = 27015;
		private const uint USBMUX_PROTOCOL_VERSION = 1;
		private const uint16 MAX_MESSAGE_SIZE = 2048;

		public signal void device_attached (DeviceId id, ProductId product_id, Udid udid);
		public signal void device_detached (DeviceId id);

		construct {
			reset ();
		}

		private void reset () {
			connection = null;
			input = null;
			output = null;

			is_processing_messages = false;
			last_tag = 1;
			mode_switch_tag = 0;
			pending_responses = new Gee.ArrayList<PendingResponse> ();
		}

		public async void establish () throws IOError {
			assert (!is_processing_messages);

			var client = new SocketClient ();

			SocketConnectable connectable;
#if WINDOWS
			connectable = new InetSocketAddress (new InetAddress.loopback (SocketFamily.IPV4), USBMUX_SERVER_PORT);
#else
			connectable = new UnixSocketAddress ("/var/run/usbmuxd");
#endif

			try {
				connection = yield client.connect_async (connectable);
				input = connection.get_input_stream ();
				output = connection.get_output_stream ();

				is_processing_messages = true;

				process_incoming_messages.begin ();
			} catch (GLib.Error e) {
				reset ();
				throw new IOError.FAILED (e.message);
			}
		}

		public async void enable_listen_mode () throws IOError {
			assert (is_processing_messages);

			var result = yield query_with_plist (create_plist ("Listen"));
			if (result != ResultCode.SUCCESS)
				throw new IOError.FAILED ("Unexpected error while trying to enable listen mode: %d", result);
		}

		public async void connect_to_port (DeviceId device_id, uint port) throws IOError {
			assert (is_processing_messages);

			var plist = create_plist ("Connect");
			plist.set_uint ("DeviceID", device_id.raw_value);
			plist.set_uint ("PortNumber", ((uint32) port << 16).to_big_endian ());

			var result = yield query_with_plist (plist, true);
			handle_connect_result (result);
		}

		public async void close () throws IOError {
			if (!is_processing_messages)
				throw new IOError.FAILED ("Client is already closed");
			is_processing_messages = false;

			input_cancellable.cancel ();
			output_cancellable.cancel ();

			var source = new IdleSource ();
			source.set_priority (Priority.LOW);
			source.set_callback (() => {
				close.callback ();
				return false;
			});
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				var conn = this.connection;
				if (conn != null)
					yield conn.close_async (Priority.DEFAULT);
			} catch (GLib.Error e) {
			}
			connection = null;
			input = null;
			output = null;
		}

		private async int query (MessageType type, uint8[]? body = null, bool is_mode_switch_request = false) throws IOError {
			uint32 tag = last_tag++;

			if (is_mode_switch_request)
				mode_switch_tag = tag;

			var request = create_message (type, tag, body);
			var pending = new PendingResponse (tag, () => query.callback ());
			pending_responses.add (pending);
			write_message.begin (request);
			yield;

			return pending.result;
		}

		private async int query_with_plist (PropertyList plist, bool is_mode_switch_request = false) throws IOError {
			var xml = plist.to_xml ();
			var size = xml.length;
			var body = new uint8[size];
			Memory.copy (body, xml, size);
			var result = yield query (MessageType.PROPERTY_LIST, body, is_mode_switch_request);
			return result;
		}

		private PropertyList create_plist (string message_type) {
			var plist = new PropertyList ();
			plist.set_string ("BundleID", "com.apple.iTunes");
			plist.set_string ("ClientVersionString", "usbmuxd-??? built for ???");
			plist.set_string ("MessageType", message_type);
			return plist;
		}

		private async void process_incoming_messages () {
			while (is_processing_messages) {
				try {
					var msg = yield read_message ();
					dispatch_message (msg);
				} catch (IOError e) {
					foreach (var pending_response in pending_responses)
						pending_response.complete (ResultCode.PROTOCOL_ERROR);
					reset ();
				}
			}
		}

		private void dispatch_message (Client.Message msg) throws IOError {
			if (msg.type != MessageType.PROPERTY_LIST)
				throw new IOError.FAILED ("Unexpected message type %u, was expecting a property list", (uint) msg.type);
			else if (msg.body_size == 0)
				throw new IOError.FAILED ("Unexpected message with empty body");

			unowned string xml = (string) msg.body;
			var plist = new PropertyList.from_xml (xml);
			var message_type = plist.get_string ("MessageType");
			if (message_type == "Result") {
				var result = plist.get_int ("Number");
				handle_result_message (msg, result);
			} else if (message_type == "Attached") {
				var attached_id = DeviceId ((uint) plist.get_int ("DeviceID"));
				var props = plist.get_plist ("Properties");
				var product_id = ProductId (props.get_int ("ProductID"));
				var udid = Udid (props.get_string ("SerialNumber"));
				device_attached (attached_id, product_id, udid);
			} else if (message_type == "Detached") {
				var detached_id = DeviceId ((uint) plist.get_int ("DeviceID"));
				device_detached (detached_id);
			} else {
				throw new IOError.FAILED ("Unexpected message type: %s", message_type);
			}
		}

		private void handle_result_message (Message msg, int result) throws IOError {
			PendingResponse match = null;
			foreach (var pending in pending_responses) {
				if (pending.tag == msg.tag) {
					match = pending;
					break;
				}
			}

			if (match == null)
				throw new IOError.FAILED ("Unexpected response with unknown tag");
			pending_responses.remove (match);
			match.complete (result);

			if (msg.tag == mode_switch_tag) {
				if (result == ResultCode.SUCCESS)
					is_processing_messages = false;
				else
					mode_switch_tag = 0;
			}
		}

		private void handle_connect_result (int result) throws IOError {
			switch (result) {
				case ResultCode.SUCCESS:
					break;
				case ResultCode.CONNECTION_REFUSED:
					throw new IOError.FAILED ("Unable to connect (connection refused)");
				case ResultCode.INVALID_REQUEST:
					throw new IOError.FAILED ("Unable to connect (invalid request)");
				default:
					throw new IOError.FAILED ("Unable to connect (error code: %d)", result);
			}
		}

		private async Message read_message () throws IOError {
			uint32 size = 0;
			yield read (&size, 4);
			size = uint.from_little_endian (size);
			if (size < 16 || size > MAX_MESSAGE_SIZE)
				throw new IOError.FAILED ("Invalid message size");

			uint32 protocol_version;
			yield read (&protocol_version, 4);

			var msg = new Message ();
			msg.size = size - 8;
			msg.data = malloc (msg.size + 1);
			msg.data[msg.size] = 0;
			msg.body = msg.data + 8;
			msg.body_size = msg.size - 8;
			yield read (msg.data, msg.size);

			uint32 * header = (void *) msg.data;
			msg.type = (MessageType) uint.from_little_endian (header[0]);
			msg.tag = uint.from_little_endian (header[1]);

			return msg;
		}

		private async void write_message (uint8[] blob) throws IOError {
			yield write (blob);
		}

		private async void read (void * buffer, size_t count) throws IOError {
			try {
				uint8 * dst = buffer;
				size_t remaining = count;
				while (remaining != 0) {
					uint8[] slice = new uint8[remaining];
					ssize_t len = yield input.read_async (slice, Priority.DEFAULT, input_cancellable);
					if (len == 0)
						throw new IOError.CLOSED ("Socket is closed");
					Memory.copy (dst, slice, len);

					dst += len;
					remaining -= len;
				}
			} catch (GLib.Error e) {
				throw new IOError.FAILED (e.message);
			}
		}

		private async void write (uint8[] buffer) throws IOError {
			try {
				size_t remaining = buffer.length;

				ssize_t len = yield output.write_async (buffer);
				remaining -= len;

				size_t offset = 0;
				while (remaining != 0) {
					uint8[] slice = buffer[offset:buffer.length];
					len = yield output.write_async (slice, Priority.DEFAULT, output_cancellable);

					offset += len;
					remaining -= len;
				}
			} catch (GLib.Error e) {
				throw new IOError.FAILED (e.message);
			}
		}

		private uint8[] create_message (MessageType type, uint32 tag, uint8[]? body = null) {
			uint body_size = 0;
			if (body != null)
				body_size = body.length;

			uint8[] blob = new uint8[16 + body_size];

			uint32 * p = (void *) blob;
			p[0] = blob.length.to_little_endian ();
			p[1] = USBMUX_PROTOCOL_VERSION.to_little_endian ();
			p[2] = ((uint) type).to_little_endian ();
			p[3] = tag.to_little_endian ();

			if (body_size != 0) {
				uint8 * blob_start = (void *) blob;
				Memory.copy (blob_start + 16, body, body_size);
			}

			return blob;
		}

		protected class Message {
			public MessageType type;
			public uint8 * body;
			public uint body_size;
			public uint32 tag;

			public uint8 * data;
			public uint size;

			~Message () {
				free (data);
			}
		}

		private class PendingResponse {
			public uint32 tag {
				get;
				private set;
			}

			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public int result {
				get;
				private set;
			}

			public PendingResponse (uint32 tag, owned CompletionHandler handler) {
				this.tag = tag;
				this.handler = (owned) handler;
			}

			public void complete (int result) {
				this.result = result;
				handler ();
			}
		}
	}

	public struct DeviceId {
		public uint raw_value {
			get;
			private set;
		}

		public DeviceId (uint raw_value) {
			this.raw_value = raw_value;
		}
	}

	public struct ProductId {
		public int raw_value {
			get;
			private set;
		}

		public ProductId (int raw_value) {
			this.raw_value = raw_value;
		}
	}

	public struct Udid {
		public string raw_value {
			get;
			private set;
		}

		public Udid (string raw_value) {
			this.raw_value = raw_value;
		}
	}

	public enum MessageType {
		RESULT		= 1,
		CONNECT		= 2,
		LISTEN		= 3,
		DEVICE_ATTACHED	= 4,
		DEVICE_DETACHED	= 5,
		PROPERTY_LIST	= 8
	}

	public enum ResultCode {
		PROTOCOL_ERROR      = -1,
		SUCCESS		    = 0,
		CONNECTION_REFUSED  = 3,
		INVALID_REQUEST	    = 5
	}
}
