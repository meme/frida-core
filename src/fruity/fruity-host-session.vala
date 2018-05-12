namespace Frida {
	public class FruityHostSessionBackend : Object, HostSessionBackend {
		private Fruity.Client control_client;

		private Gee.HashSet<uint> devices = new Gee.HashSet<uint> ();
		private Gee.HashMap<uint, FruityRemoteProvider> remote_providers = new Gee.HashMap<uint, FruityRemoteProvider> ();
		private Gee.HashMap<uint, FruityLockdownProvider> lockdown_providers = new Gee.HashMap<uint, FruityLockdownProvider> ();

		private Gee.Promise<bool> start_request;
		private StartedHandler started_handler;
		private delegate void StartedHandler ();

		public async void start () {
			started_handler = () => start.callback ();
			var timeout_source = new TimeoutSource (100);
			timeout_source.set_callback (() => {
				start.callback ();
				return false;
			});
			timeout_source.attach (MainContext.get_thread_default ());
			do_start.begin ();
			yield;
			started_handler = null;
			timeout_source.destroy ();
		}

		private async void do_start () {
			start_request = new Gee.Promise<bool> ();

			bool success = true;

			control_client = new Fruity.Client ();
			control_client.device_attached.connect ((id, product_id, udid) => {
				add_device.begin (id, product_id, udid);
			});
			control_client.device_detached.connect ((id) => {
				remove_device (id);
			});

			try {
				yield control_client.establish ();
				yield control_client.enable_listen_mode ();
			} catch (IOError e) {
				success = false;
			}

			if (success) {
				/* perform a dummy-request to flush out any pending device attach notifications */
				try {
					yield control_client.connect_to_port (uint.MAX, uint.MAX);
					assert_not_reached ();
				} catch (IOError expected_error) {
				}
			}

			start_request.set_value (success);

			if (!success)
				yield stop ();

			if (started_handler != null)
				started_handler ();
		}

		public async void stop () {
			try {
				yield start_request.future.wait_async ();
			} catch (Gee.FutureError e) {
				assert_not_reached ();
			}

			if (control_client != null) {
				try {
					yield control_client.close ();
				} catch (IOError e) {
				}
				control_client = null;
			}

			devices.clear ();

			foreach (var provider in lockdown_providers.values) {
				provider_unavailable (provider);
				yield provider.close ();
			}
			lockdown_providers.clear ();

			foreach (var provider in remote_providers.values) {
				provider_unavailable (provider);
				yield provider.close ();
			}
			remote_providers.clear ();
		}

		private async void add_device (uint id, int product_id, string udid) {
			if (devices.contains (id))
				return;
			devices.add (id);

			string? name = null;
			ImageData? icon_data = null;

			bool got_details = false;
			for (int i = 1; !got_details && devices.contains (id); i++) {
				try {
					_extract_details_for_device (product_id, udid, out name, out icon_data);
					got_details = true;
				} catch (Error e) {
					if (i != 20) {
						var source = new TimeoutSource.seconds (1);
						source.set_callback (() => {
							add_device.callback ();
							return false;
						});
						source.attach (MainContext.get_thread_default ());
						yield;
					} else {
						break;
					}
				}
			}
			if (!devices.contains (id))
				return;
			if (!got_details) {
				remove_device (id);
				return;
			}

			var icon = Image.from_data (icon_data);

			var remote_provider = new FruityRemoteProvider (name, icon, id, product_id, udid);
			remote_providers[id] = remote_provider;

			var lockdown_provider = new FruityLockdownProvider (name, icon, id, product_id, udid);
			lockdown_providers[id] = lockdown_provider;

			provider_available (remote_provider);
			provider_available (lockdown_provider);
		}

		private void remove_device (uint id) {
			if (!devices.contains (id))
				return;
			devices.remove (id);

			FruityLockdownProvider lockdown_provider;
			if (lockdown_providers.unset (id, out lockdown_provider))
				lockdown_provider.close.begin ();

			FruityRemoteProvider remote_provider;
			if (remote_providers.unset (id, out remote_provider))
				remote_provider.close.begin ();
		}

		public extern static void _extract_details_for_device (int product_id, string udid, out string name, out ImageData? icon) throws Error;
	}

	public class FruityRemoteProvider : Object, HostSessionProvider {
		public string id {
			get { return device_udid; }
		}

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

		public uint device_id {
			get;
			construct;
		}

		public int device_product_id {
			get;
			construct;
		}

		public string device_udid {
			get;
			construct;
		}

		private Gee.HashSet<Entry> entries = new Gee.HashSet<Entry> ();

		private const uint DEFAULT_SERVER_PORT = 27042;

		public FruityRemoteProvider (string name, Image? icon, uint device_id, int device_product_id, string device_udid) {
			Object (
				device_name: name,
				device_icon: icon,
				device_id: device_id,
				device_product_id: device_product_id,
				device_udid: device_udid
			);
		}

		public async void close () {
			while (!entries.is_empty) {
				var iterator = entries.iterator ();
				iterator.next ();
				var entry = iterator.get ();

				entries.remove (entry);

				yield destroy_entry (entry, SessionDetachReason.APPLICATION_REQUESTED);
			}
		}

		public async HostSession create (string? location = null) throws Error {
			uint port = (location != null) ? (uint) int.parse (location) : DEFAULT_SERVER_PORT;
			foreach (var entry in entries) {
				if (entry.port == port)
					throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			}

			Fruity.Client client = new Fruity.Client ();
			DBusConnection connection;
			try {
				yield client.establish ();
				yield client.connect_to_port (device_id, port);
				connection = yield new DBusConnection (client.connection, null, DBusConnectionFlags.AUTHENTICATION_CLIENT);
			} catch (GLib.Error e) {
				if (e is IOError.CONNECTION_REFUSED)
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server");
				else
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server: " + e.message);
			}

			HostSession session;
			try {
				session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION);
			} catch (IOError e) {
				throw new Error.PROTOCOL ("Incompatible frida-server version");
			}

			var entry = new Entry (port, client, connection, session);
			entry.agent_session_closed.connect (on_agent_session_closed);
			entries.add (entry);

			connection.on_closed.connect (on_connection_closed);

			return session;
		}

		public async void destroy (HostSession host_session) throws Error {
			foreach (var entry in entries) {
				if (entry.host_session == host_session) {
					entries.remove (entry);
					yield destroy_entry (entry, SessionDetachReason.APPLICATION_REQUESTED);
					return;
				}
			}
			throw new Error.INVALID_ARGUMENT ("Invalid host session");
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id) throws Error {
			foreach (var entry in entries) {
				if (entry.host_session == host_session)
					return yield entry.obtain_agent_session (agent_session_id);
			}
			throw new Error.INVALID_ARGUMENT ("Invalid host session");
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			Entry entry_to_remove = null;
			foreach (var entry in entries) {
				if (entry.connection == connection) {
					entry_to_remove = entry;
					break;
				}
			}
			assert (entry_to_remove != null);

			entries.remove (entry_to_remove);
			destroy_entry.begin (entry_to_remove, SessionDetachReason.SERVER_TERMINATED);
		}

		private void on_agent_session_closed (AgentSessionId id, SessionDetachReason reason) {
			agent_session_closed (id, reason);
		}

		private async void destroy_entry (Entry entry, SessionDetachReason reason) {
			entry.connection.on_closed.disconnect (on_connection_closed);
			yield entry.destroy (reason);
			entry.agent_session_closed.disconnect (on_agent_session_closed);
			host_session_closed (entry.host_session);
		}

		private class Entry : Object {
			public signal void agent_session_closed (AgentSessionId id, SessionDetachReason reason);

			public uint port {
				get;
				construct;
			}

			public Fruity.Client client {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public HostSession host_session {
				get;
				construct;
			}

			private Gee.HashMap<AgentSessionId?, AgentSession> agent_session_by_id = new Gee.HashMap<AgentSessionId?, AgentSession> ();

			public Entry (uint port, Fruity.Client client, DBusConnection connection, HostSession host_session) {
				Object (port: port, client: client, connection: connection, host_session: host_session);

				host_session.agent_session_destroyed.connect (on_agent_session_destroyed);
			}

			public async void destroy (SessionDetachReason reason) {
				host_session.agent_session_destroyed.disconnect (on_agent_session_destroyed);

				foreach (var agent_session_id in agent_session_by_id.keys)
					agent_session_closed (agent_session_id, reason);
				agent_session_by_id.clear ();

				try {
					yield connection.close ();
				} catch (GLib.Error e) {
				}
			}

			public async AgentSession obtain_agent_session (AgentSessionId id) throws Error {
				AgentSession session = agent_session_by_id[id];
				if (session == null) {
					try {
						session = yield connection.get_proxy (null, ObjectPath.from_agent_session_id (id));
						agent_session_by_id[id] = session;
					} catch (IOError proxy_error) {
						throw new Error.INVALID_ARGUMENT (proxy_error.message);
					}
				}
				return session;
			}

			private void on_agent_session_destroyed (AgentSessionId id, SessionDetachReason reason) {
				agent_session_by_id.unset (id);
				agent_session_closed (id, reason);
			}
		}
	}

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
			get { return HostSessionProviderKind.LOCAL_TETHER; }
		}

		public string device_name {
			get;
			construct;
		}

		public Image? device_icon {
			get;
			construct;
		}

		public uint device_id {
			get;
			construct;
		}

		public int device_product_id {
			get;
			construct;
		}

		public string device_udid {
			get;
			construct;
		}

		public FruityLockdownProvider (string name, Image? icon, uint device_id, int device_product_id, string device_udid) {
			Object (
				device_name: name,
				device_icon: icon,
				device_id: device_id,
				device_product_id: device_product_id,
				device_udid: device_udid
			);
		}

		construct {
			_id = device_udid + ":lockdown";
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
