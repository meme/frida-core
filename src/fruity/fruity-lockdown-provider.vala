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
			try {
				var lockdown = yield Fruity.LockdownClient.open (device_details);
				try {
					var installation_proxy = yield Fruity.InstallationProxyClient.open (lockdown);
					var apps = yield installation_proxy.enumerate_applications ();
					print ("Got %u apps:\n", apps.size);
					foreach (var app in apps) {
						printerr ("\t<identifier='%s' name='%s' path='%s' container='%s' debuggable=%s>\n",
							app.identifier, app.name, app.path, app.container, app.debuggable.to_string ());
					}
				} finally {
					yield lockdown.close ();
				}
			} catch (Fruity.LockdownError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			} catch (Fruity.InstallationProxyError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			throw new Error.NOT_SUPPORTED ("Not yet fully implemented");
		}

		public async void destroy (HostSession host_session) throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id) throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}
	}
}
