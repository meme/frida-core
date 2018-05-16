namespace Frida.Fruity {
	public class LockdownSession : Object, AsyncInitable {
		public DeviceDetails device_details {
			get;
			construct;
		}

		private UsbmuxClient transport;
		private PropertyRpcClient client;

		private const uint LOCKDOWN_PORT = 62078;

		private LockdownSession (DeviceDetails device_details) {
			Object (device_details: device_details);
		}

		public static async LockdownSession open (DeviceDetails device_details, Cancellable? cancellable = null) throws LockdownError {
			var session = new LockdownSession (device_details);

			try {
				yield session.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				assert (e is LockdownError);
				throw (LockdownError) e;
			}

			return session;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws LockdownError {
			var device = device_details;

			try {
				transport = yield UsbmuxClient.open (cancellable);

				var pair_record = yield transport.read_pair_record (device.udid);

				yield transport.connect_to_port (device.id, LOCKDOWN_PORT);

				client = new PropertyRpcClient (transport.connection);
				client.open ();

				var type = yield query_type ();
				printerr ("type: %s\n", type);

				yield start_session (pair_record);
			} catch (UsbmuxError e) {
				throw new LockdownError.FAILED ("%s", e.message);
			}

			return true;
		}

		public async void close () {
			if (client != null) {
				yield client.close ();
				client = null;
			}

			if (transport != null) {
				yield transport.close ();
				transport = null;
			}
		}

		public async UsbmuxClient start_service (string name) throws LockdownError {
			try {
				var request = client.create_request ("StartService");
				request.set_string ("Service", name);

				var response = yield client.query (request);
				printerr ("response: %s\n", response.to_xml ());

				var service_transport = yield UsbmuxClient.open ();
				yield service_transport.connect_to_port (device_details.id, response.get_int ("Port"));
				return service_transport;
			} catch (PropertyRpcError e) {
				throw error_from_rpc (e);
			} catch (PropertyListError e) {
				throw response_error_from_property_list (e);
			} catch (UsbmuxError e) {
				throw new LockdownError.FAILED ("%s", e.message);
			}
		}

		private async string query_type () throws LockdownError {
			try {
				var response = yield client.query (client.create_request ("QueryType"));

				return response.get_string ("Type");
			} catch (PropertyRpcError e) {
				throw error_from_rpc (e);
			} catch (PropertyListError e) {
				throw response_error_from_property_list (e);
			}
		}

		private async void start_session (PropertyList pair_record) throws LockdownError {
			string host_id, system_buid;
			try {
				host_id = pair_record.get_string ("HostID");
				system_buid = pair_record.get_string ("SystemBUID");
			} catch (PropertyListError e) {
				throw new LockdownError.FAILED ("Invalid pair record: %s", e.message);
			}

			try {
				var request = client.create_request ("StartSession");
				request.set_string ("HostID", host_id);
				request.set_string ("SystemBUID", system_buid);

				var response = yield client.query (request);
				if (response.has_key ("Error"))
					throw new LockdownError.FAILED ("Unexpected response: %s", response.get_string ("Error"));

				if (response.get_boolean ("EnableSessionSSL"))
					yield client.enable_encryption (pair_record);
			} catch (PropertyRpcError e) {
				throw error_from_rpc (e);
			} catch (PropertyListError e) {
				throw response_error_from_property_list (e);
			}
		}

		private LockdownError error_from_rpc (PropertyRpcError e) {
			if (e is PropertyRpcError.CONNECTION_CLOSED)
				return new LockdownError.CONNECTION_CLOSED ("%s", e.message);
			return new LockdownError.FAILED ("%s", e.message);
		}

		private LockdownError response_error_from_property_list (PropertyListError e) {
			return new LockdownError.PROTOCOL ("Unexpected response: %s", e.message);
		}
	}

	public errordomain LockdownError {
		FAILED,
		CONNECTION_CLOSED,
		PROTOCOL
	}
}
