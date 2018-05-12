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
}
