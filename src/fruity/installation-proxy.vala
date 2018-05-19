namespace Frida.Fruity {
	public class InstallationProxyClient : Object, AsyncInitable {
		public LockdownClient lockdown {
			get;
			construct;
		}

		private PlistServiceClient service;

		private InstallationProxyClient (LockdownClient lockdown) {
			Object (lockdown: lockdown);
		}

		public static async InstallationProxyClient open (LockdownClient lockdown, Cancellable? cancellable = null) throws InstallationProxyError {
			var client = new InstallationProxyClient (lockdown);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				assert (e is InstallationProxyError);
				throw (InstallationProxyError) e;
			}

			return client;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws InstallationProxyError {
			try {
				var stream = yield lockdown.start_service ("com.apple.mobile.installation_proxy");

				service = new PlistServiceClient (stream);
			} catch (LockdownError e) {
				throw new InstallationProxyError.FAILED ("%s", e.message);
			}

			return true;
		}

		public async void close () {
			yield service.close ();
		}

		public async Gee.ArrayList<ApplicationDetails> enumerate_applications () throws InstallationProxyError {
			try {
				var options = new PlistDict ();

				var request = create_request ("Browse");
				request.set_dict ("ClientOptions", options);

				var reader = yield service.begin_query (request);

				var apps = new Gee.ArrayList<ApplicationDetails> ();

				string status = "";
				do {
					var response = yield reader.read ();
					printerr ("Got response: %s\n", response.to_xml ());

					status = response.get_string ("Status");
				} while (status != "Complete");

				return apps;
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} catch (PlistError e) {
				throw error_from_plist (e);
			}
		}

		private Plist create_request (string command) {
			var request = new Plist ();
			request.set_string ("Command", command);
			return request;
		}

		private InstallationProxyError error_from_service (PlistServiceError e) {
			if (e is PlistServiceError.CONNECTION_CLOSED)
				return new InstallationProxyError.CONNECTION_CLOSED ("%s", e.message);
			return new InstallationProxyError.FAILED ("%s", e.message);
		}

		private InstallationProxyError error_from_plist (PlistError e) {
			return new InstallationProxyError.PROTOCOL ("Unexpected response: %s", e.message);
		}
	}

	public errordomain InstallationProxyError {
		FAILED,
		CONNECTION_CLOSED,
		PROTOCOL
	}

	public class ApplicationDetails : Object {
		public string identifier {
			get;
			construct;
		}

		public string name {
			get;
			construct;
		}

		public ApplicationDetails (string identifier, string name) {
			Object (
				identifier: identifier,
				name: name
			);
		}
	}
}
