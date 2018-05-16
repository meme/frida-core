namespace Frida.Fruity {
	public class LockdownSession : Object {
		public DeviceDetails device_details {
			get;
			construct;
		}

		public uint port {
			get;
			construct;
		}

		private UsbmuxClient transport = new UsbmuxClient ();
		private IOStream connection;
		private InputStream input;
		private OutputStream output;
		private Cancellable cancellable = new Cancellable ();

		private bool is_processing_messages;
		private Gee.ArrayQueue<PendingResponse> pending_responses = new Gee.ArrayQueue<PendingResponse> ();

		private const uint LOCKDOWN_PORT = 62078;
		private const uint32 MAX_MESSAGE_SIZE = 128 * 1024;

		private LockdownSession (DeviceDetails device_details, uint port) {
			Object (
				device_details: device_details,
				port: port
			);
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

		public static async LockdownSession open (DeviceDetails device_details) throws Error {
			var session = new LockdownSession (device_details, LOCKDOWN_PORT);
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

		public async UsbmuxClient start_service (string name) throws Error {
			assert (is_processing_messages);

			var request = create_request ("StartService");
			request.set_string ("Service", name);

			try {
				var response = yield query (request);

				var service_transport = new UsbmuxClient ();
				yield service_transport.establish ();
				yield service_transport.connect_to_port (device_details.id, response.get_int ("Port"));
				return service_transport;
			} catch (IOError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private async void establish () throws Error {
			try {
				yield transport.establish ();

				var pair_record = yield transport.read_pair_record (device_details.udid);

				yield transport.connect_to_port (device_details.id, port);

				connection = transport.connection;
				input = connection.get_input_stream ();
				output = connection.get_output_stream ();

				is_processing_messages = true;
				process_incoming_messages.begin ();

				var type = yield query_type ();

				yield start_session (pair_record);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
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
			if (response.has_key ("Error"))
				throw new IOError.FAILED ("Unexpected StartSession response: %s", response.get_string ("Error"));

			if (response.get_boolean ("EnableSessionSSL")) {
				is_processing_messages = false;

				var source = new IdleSource ();
				source.set_callback (() => {
					start_session.callback ();
					return false;
				});
				source.attach (MainContext.get_thread_default ());
				yield;

				try {
					var connection = TlsClientConnection.new (this.connection, null);
					connection.accept_certificate.connect (on_accept_certificate);

					var host_cert = pair_record.get_bytes_as_string ("HostCertificate");
					var host_key = pair_record.get_bytes_as_string ("HostPrivateKey");
					var host_certificate = new TlsCertificate.from_pem (string.join ("\n", host_cert, host_key), -1);
					connection.set_certificate (host_certificate);

					yield connection.handshake_async (Priority.DEFAULT, cancellable);

					this.connection = connection;
					this.input = connection.get_input_stream ();
					this.output = connection.get_output_stream ();

					is_processing_messages = true;
					process_incoming_messages.begin ();
				} catch (GLib.Error e) {
					throw new IOError.FAILED ("%s", e.message);
				}
			}
		}

		private bool on_accept_certificate (TlsCertificate peer_cert, TlsCertificateFlags errors) {
			return true;
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
