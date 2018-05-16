namespace Frida.Fruity {
	public class PropertyRpcClient : Object {
		public IOStream stream {
			get;
			construct;
		}
		private TlsClientConnection? tls_connection;
		private InputStream input;
		private OutputStream output;
		private Cancellable cancellable = new Cancellable ();

		private bool is_processing_messages;
		private Gee.ArrayQueue<PendingResponse> pending_responses = new Gee.ArrayQueue<PendingResponse> ();

		private const uint32 MAX_MESSAGE_SIZE = 128 * 1024;

		public PropertyRpcClient (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			input = stream.get_input_stream ();
			output = stream.get_output_stream ();
		}

		public void open () {
			is_processing_messages = true;
			process_incoming_messages.begin ();
		}

		public async void close () {
			if (!is_processing_messages)
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
		}

		public async void enable_encryption (PropertyList pair_record) throws PropertyRpcError {
			is_processing_messages = false;

			var source = new IdleSource ();
			source.set_callback (() => {
				enable_encryption.callback ();
				return false;
			});
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				var connection = TlsClientConnection.new (stream, null);
				connection.accept_certificate.connect (on_accept_certificate);

				var host_cert = pair_record.get_bytes_as_string ("HostCertificate");
				var host_key = pair_record.get_bytes_as_string ("HostPrivateKey");
				var host_certificate = new TlsCertificate.from_pem (string.join ("\n", host_cert, host_key), -1);
				connection.set_certificate (host_certificate);

				yield connection.handshake_async (Priority.DEFAULT, cancellable);

				this.tls_connection = connection;
				this.input = connection.get_input_stream ();
				this.output = connection.get_output_stream ();

				is_processing_messages = true;
				process_incoming_messages.begin ();
			} catch (GLib.Error e) {
				throw new PropertyRpcError.FAILED ("%s", e.message);
			}
		}

		private bool on_accept_certificate (TlsCertificate peer_cert, TlsCertificateFlags errors) {
			return true;
		}

		public async PropertyList query (PropertyList request) throws PropertyRpcError {
			var msg = create_message (request);

			var pending = new PendingResponse (() => query.callback ());
			pending_responses.offer_tail (pending);
			write_message.begin (msg);
			yield;

			var response = pending.response;
			if (response == null)
				throw pending.error;

			return response;
		}

		public PropertyList create_request (string request_type) {
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
				} catch (PropertyRpcError e) {
					foreach (var pending_response in pending_responses)
						pending_response.complete_with_error (e);
				}
			}
		}

		private void handle_response_message (PropertyList response) throws PropertyRpcError {
			var pending = pending_responses.poll_head ();
			if (pending == null)
				throw new PropertyRpcError.PROTOCOL ("Unexpected reply");
			pending.complete_with_response (response);
		}

		private async PropertyList read_message () throws PropertyRpcError {
			uint32 size = 0;
			unowned uint8[] size_buf = ((uint8[]) &size)[0:4];
			yield read (size_buf);
			size = uint32.from_big_endian (size);
			if (size < 1 || size > MAX_MESSAGE_SIZE)
				throw new PropertyRpcError.PROTOCOL ("Invalid message size");

			var body_buf = new uint8[size + 1];
			body_buf[size] = 0;
			yield read (body_buf[0:size]);

			unowned string body_xml = (string) body_buf;
			try {
				return new PropertyList.from_xml (body_xml);
			} catch (PropertyListError e) {
				throw new PropertyRpcError.PROTOCOL ("Malformed message: %s", e.message);
			}
		}

		private async void read (uint8[] buffer) throws PropertyRpcError {
			size_t bytes_read;
			try {
				yield input.read_all_async (buffer, Priority.DEFAULT, cancellable, out bytes_read);
			} catch (GLib.Error e) {
				throw new PropertyRpcError.CONNECTION_CLOSED ("%s", e.message);
			}
			if (bytes_read == 0)
				throw new PropertyRpcError.CONNECTION_CLOSED ("Connection closed");
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

			public PropertyRpcError? error {
				get;
				private set;
			}

			public PendingResponse (owned CompletionHandler handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_response (PropertyList? response) {
				this.response = response;
				handler ();
			}

			public void complete_with_error (PropertyRpcError? error) {
				this.error = error;
				handler ();
			}
		}
	}

	public errordomain PropertyRpcError {
		FAILED,
		CONNECTION_CLOSED,
		PROTOCOL
	}
}
