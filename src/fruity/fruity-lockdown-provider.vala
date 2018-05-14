using Frida.Fruity;

namespace Frida {
	public class FruityLockdownProvider : Object, HostSessionProvider {
		public string id {
			get { return _id; }
		}
		private string _id;

		public string name {
			get { return device_name; }
		}

		public Image? icon {
			get { return device_icon; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.USB; }
		}

		public string device_name {
			get;
			construct;
		}

		public Image? device_icon {
			get;
			construct;
		}

		public Fruity.DeviceDetails device_details {
			get;
			construct;
		}

		public FruityLockdownProvider (string name, Image? icon, Fruity.DeviceDetails details) {
			Object (
				device_name: name,
				device_icon: icon,
				device_details: details
			);
		}

		construct {
			_id = device_details.udid.raw_value + ":lockdown";
		}

		public async void close () {
		}

		public async HostSession create (string? location = null) throws Error {
			var session = yield LockdownSession.open (device_details);
			yield session.close ();

			throw new Error.NOT_SUPPORTED ("Not yet fully implemented");
		}

		public async void destroy (HostSession host_session) throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id) throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}
	}

	private class LockdownSession : Object {
		public Fruity.DeviceDetails device_details {
			get;
			construct;
		}

		private Fruity.UsbmuxClient transport = new Fruity.UsbmuxClient ();
		private SocketConnection connection;
		private InputStream input;
		private OutputStream output;
		private Cancellable cancellable = new Cancellable ();

		private bool is_processing_messages;
		private Gee.ArrayQueue<PendingResponse> pending_responses = new Gee.ArrayQueue<PendingResponse> ();

		private const uint LOCKDOWN_PORT = 62078;
		private const uint32 MAX_MESSAGE_SIZE = 128 * 1024;

		private LockdownSession (Fruity.DeviceDetails device_details) {
			Object (device_details: device_details);
		}

		construct {
			reset ();
		}

		private void reset () {
			connection = null;
			input = null;
			output = null;

			is_processing_messages = false;
		}

		public static async LockdownSession open (Fruity.DeviceDetails device_details) throws Error {
			var session = new LockdownSession (device_details);
			yield session.establish ();
			return session;
		}

		public async void close () {
			if (!is_processing_messages || transport == null)
				return;
			is_processing_messages = false;

			cancellable.cancel ();

			var source = new IdleSource ();
			source.set_priority (Priority.LOW);
			source.set_callback (() => {
				close.callback ();
				return false;
			});
			source.attach (MainContext.get_thread_default ());
			yield;

			yield transport.close ();
			transport = null;
		}

		private async void establish () throws Error {
			try {
				yield transport.establish ();

				var pair_record = yield transport.read_pair_record (device_details.udid);

				yield transport.connect_to_port (device_details.id, LOCKDOWN_PORT);

				connection = transport.connection;
				input = connection.get_input_stream ();
				output = connection.get_output_stream ();

				is_processing_messages = true;

				process_incoming_messages.begin ();

				var type = yield query_type ();
				printerr ("query_type() => %s\n", type);

				yield start_session (pair_record);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED (e.message);
			}

			printerr ("CONNECTED!\n");
		}

		private async string query_type () throws IOError {
			assert (is_processing_messages);

			var response = yield query (create_request ("QueryType"));

			return response.get_string ("Type");
		}

		private async void start_session (PropertyList pair_record) throws IOError {
			assert (is_processing_messages);

			var request = create_request ("StartSession");
			request.set_string ("HostID", pair_record.get_string ("HostID"));
			request.set_string ("SystemBUID", pair_record.get_string ("SystemBUID"));
			var response = yield query (request);
			if (response.has_key ("Error")) {
				throw new IOError.FAILED ("Unexpected StartSession response: %s", response.get_string ("Error"));
			}

			printerr ("response: %s\n", response.to_xml ());
		}

		private async PropertyList query (PropertyList request) throws IOError {
			var msg = create_message (request);

			var pending = new PendingResponse (() => query.callback ());
			pending_responses.offer_tail (pending);
			write_message.begin (msg);
			yield;

			var response = pending.response;
			if (response == null)
				throw new IOError.CONNECTION_CLOSED ("Connection closed");

			return response;
		}

		private PropertyList create_request (string request_type) {
			var request = new PropertyList ();
			request.set_string ("Request", request_type);
			request.set_string ("Label", "Xcode");
			request.set_string ("ProtocolVersion", "2");
			return request;
		}

		private async void process_incoming_messages () {
			while (is_processing_messages) {
				try {
					var msg = yield read_message ();
					handle_response_message (msg);
				} catch (GLib.Error e) {
					foreach (var pending_response in pending_responses)
						pending_response.complete (null);
					reset ();
				}
			}
		}

		private void handle_response_message (PropertyList response) throws IOError {
			var pending = pending_responses.poll_head ();
			if (pending == null)
				throw new IOError.FAILED ("Unexpected reply");
			pending.complete (response);
		}

		private async PropertyList read_message () throws GLib.Error {
			size_t bytes_read;

			uint32 size = 0;
			unowned uint8[] size_buf = ((uint8[]) &size)[0:4];
			yield input.read_all_async (size_buf, Priority.DEFAULT, cancellable, out bytes_read);
			if (bytes_read == 0)
				throw new IOError.CONNECTION_CLOSED ("Connection closed");
			size = uint32.from_big_endian (size);
			if (size < 1 || size > MAX_MESSAGE_SIZE)
				throw new IOError.FAILED ("Invalid message size");

			var body_buf = new uint8[size + 1];
			body_buf[size] = 0;
			yield input.read_all_async (body_buf[0:size], Priority.DEFAULT, cancellable, out bytes_read);
			if (bytes_read == 0)
				throw new IOError.CONNECTION_CLOSED ("Connection closed");

			unowned string body_xml = (string) body_buf;
			var body = new PropertyList.from_xml (body_xml);

			return body;
		}

		private async void write_message (uint8[] blob) throws GLib.Error {
			size_t bytes_written;
			yield output.write_all_async (blob, Priority.DEFAULT, cancellable, out bytes_written);
		}

		private uint8[] create_message (PropertyList request) {
			var xml = request.to_xml ();
			unowned uint8[] body = ((uint8[]) xml)[0:xml.length];

			uint8[] blob = new uint8[4 + body.length];

			uint32 * size = (void *) blob;
			*size = body.length.to_big_endian ();

			uint8 * blob_start = (void *) blob;
			Memory.copy (blob_start + 4, body, body.length);

			return blob;
		}

		private class PendingResponse {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public PropertyList? response {
				get;
				private set;
			}

			public PendingResponse (owned CompletionHandler handler) {
				this.handler = (owned) handler;
			}

			public void complete (PropertyList? response) {
				this.response = response;
				handler ();
			}
		}
	}
}
