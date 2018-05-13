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

		public Fruity.DeviceId device_id {
			get;
			construct;
		}

		public Fruity.Udid device_udid {
			get;
			construct;
		}

		public FruityLockdownProvider (string name, Image? icon, Fruity.DeviceId id, Fruity.Udid udid) {
			Object (
				device_name: name,
				device_icon: icon,
				device_id: id,
				device_udid: udid
			);
		}

		construct {
			_id = device_udid.raw_value + ":lockdown";
		}

		public async void close () {
		}

		public async HostSession create (string? location = null) throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async void destroy (HostSession host_session) throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id) throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}
	}
}
