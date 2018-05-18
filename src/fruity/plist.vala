namespace Frida.Fruity {
	public class Plist : Dict {
		public Plist.from_xml (string xml) throws PlistError {
			try {
				var parser = new XmlParser (this);
				parser.parse (xml);
			} catch (MarkupError e) {
				throw new PlistError.INVALID_DATA (e.message);
			}
		}

		public string to_xml () {
			var builder = new StringBuilder ();
			var writer = new XmlWriter (builder);
			writer.write_plist (this);
			return builder.str;
		}

		private class XmlParser : Object {
			public Plist plist {
				get;
				construct;
			}

			private const MarkupParser parser = {
				on_start_element,
				on_end_element,
				on_text,
				null,
				null
			};

			private Gee.Deque<Dict> stack;
			private KeyValuePair current_pair;

			public XmlParser (Plist plist) {
				Object (plist: plist);
			}

			public void parse (string xml) throws MarkupError {
				stack = new Gee.LinkedList<Plist> ();
				current_pair = null;

				var context = new MarkupParseContext (parser, 0, this, null);
				context.parse (xml, -1);

				stack = null;
				current_pair = null;
			}

			private void on_start_element (MarkupParseContext context, string element_name, string[] attribute_names, string[] attribute_values) throws MarkupError {
				if (stack.is_empty) {
					if (element_name == "dict")
						stack.offer_head (plist);
					return;
				} else if (current_pair == null) {
					if (element_name == "key")
						current_pair = new KeyValuePair ();
					return;
				}

				if (current_pair.type == null) {
					current_pair.type = element_name;

					if (current_pair.type == "dict") {
						var parent = stack.peek ();

						var dict = new Dict ();
						stack.offer_head (dict);
						var dict_value = Value (typeof (Dict));
						dict_value.set_object (dict);
						parent.set_value (current_pair.key, dict_value);

						current_pair = null;
					}
				}
			}

			private void on_end_element (MarkupParseContext context, string element_name) throws MarkupError {
				if (element_name == "dict")
					stack.poll ();
			}

			private void on_text (MarkupParseContext context, string text, size_t text_len) throws MarkupError {
				if (current_pair == null)
					return;

				if (current_pair.key == null) {
					current_pair.key = text;
				} else if (current_pair.type != null) {
					current_pair.val = text;

					var val = current_pair.to_value ();
					if (val != null) {
						var current_plist = stack.peek ();
						current_plist.set_value (current_pair.key, val);
					}

					current_pair = null;
				}
			}

			private class KeyValuePair {
				public string? key;
				public string? type;
				public string? val;

				public Value? to_value () {
					Value? result = null;
					if (type == "true") {
						result = Value (typeof (bool));
						result.set_boolean (true);
					} else if (type == "false") {
						result = Value (typeof (bool));
						result.set_boolean (false);
					} else if (type == "integer") {
						result = Value (typeof (int));
						result.set_int (int.parse (val));
					} else if (type == "string") {
						result = Value (typeof (string));
						result.set_string (val);
					} else if (type == "data") {
						result = Value (typeof (Bytes));
						result.take_boxed (new Bytes.take (Base64.decode (val)));
					}

					return result;
				}
			}
		}

		private class XmlWriter {
			private unowned StringBuilder builder;
			private uint level = 0;

			public XmlWriter (StringBuilder builder) {
				this.builder = builder;
			}

			public void write_plist (Plist plist) {
				write_line ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
				write_line ("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">");
				write_line ("<plist version=\"1.0\">");

				write_dict (plist);

				write_line ("</plist>");
			}

			public void write_dict (Dict dict) {
				write_line ("<dict>");
				level++;

				var keys = new Gee.ArrayList<string> ();
				var key_array = dict.get_keys ();
				foreach (var key in key_array)
					keys.add (key);
				keys.sort ();

				foreach (var key in keys) {
					write_tag ("key", key);

					Value val;
					try {
						val = dict.get_value (key);
					} catch (PlistError e) {
						assert_not_reached ();
					}

					write_value (val);
				}

				level--;
				write_line ("</dict>");
			}

			public void write_value (Value val) {
				var type = val.type ();
				if (type == typeof (bool)) {
					write_tag (val.get_boolean ().to_string ());
				} else if (type == typeof (int)) {
					write_tag ("integer", val.get_int ().to_string ());
				} else if (type == typeof (uint)) {
					write_tag ("integer", val.get_uint ().to_string ());
				} else if (type == typeof (string)) {
					write_tag ("string", Markup.escape_text (val.get_string ()));
				} else if (type == typeof (Bytes)) {
					unowned Bytes bytes = (Bytes) val.get_boxed ();
					write_tag ("data", Base64.encode (bytes.get_data ()));
				} else if (type == typeof (Dict)) {
					write_dict (val.get_object () as Dict);
				}
			}

			private void write_tag (string name, string? content = null) {
				if (content != null)
					write_line ("<" + name + ">" + content + "</" + name + ">");
				else
					write_line ("<" + name + "/>");
			}

			private void write_line (string line) {
				for (uint i = 0; i != level; i++)
					builder.append_c ('\t');
				builder.append (line);
				builder.append ("\n");
			}
		}
	}

	public class Dict : Object {
		private Gee.HashMap<string, Value?> storage = new Gee.HashMap<string, Value?> ();

		public string[] get_keys () {
			return storage.keys.to_array ();
		}

		public bool has_key (string key) {
			return storage.has_key (key);
		}

		public bool get_boolean (string key) throws PlistError {
			return get_value (key, typeof (bool)).get_boolean ();
		}

		public void set_boolean (string key, bool val) {
			var gval = Value (typeof (bool));
			gval.set_boolean (val);
			set_value (key, gval);
		}

		public int get_int (string key) throws PlistError {
			return get_value (key, typeof (int)).get_int ();
		}

		public void set_int (string key, int val) {
			var gval = Value (typeof (int));
			gval.set_int (val);
			set_value (key, gval);
		}

		public uint get_uint (string key) throws PlistError {
			return get_value (key, typeof (uint)).get_uint ();
		}

		public void set_uint (string key, uint val) {
			var gval = Value (typeof (uint));
			gval.set_uint (val);
			set_value (key, gval);
		}

		public string get_string (string key) throws PlistError {
			return get_value (key, typeof (string)).get_string ();
		}

		public void set_string (string key, string str) {
			var gval = Value (typeof (string));
			gval.set_string (str);
			set_value (key, gval);
		}

		public unowned Bytes get_bytes (string key) throws PlistError {
			return (Bytes) get_value (key, typeof (Bytes)).get_boxed ();
		}

		public string get_bytes_as_string (string key) throws PlistError {
			var bytes = get_bytes (key);
			unowned string unterminated_str = (string) bytes.get_data ();
			return unterminated_str[0:bytes.length];
		}

		public void set_bytes (string key, Bytes val) {
			var gval = Value (typeof (Bytes));
			gval.set_boxed (val);
			set_value (key, gval);
		}

		public Dict get_dict (string key) throws PlistError {
			return get_value (key, typeof (Dict)).get_object () as Dict;
		}

		public void set_dict (string key, Dict dict) {
			var gval = Value (typeof (Dict));
			gval.set_object (dict);
			set_value (key, gval);
		}

		public Value get_value (string key, GLib.Type expected_type = GLib.Type.INVALID) throws PlistError {
			var val = storage[key];
			if (val == null)
				throw new PlistError.KEY_NOT_FOUND ("Property list key '%s' does not exist".printf (key));
			if (expected_type != Type.INVALID && !val.holds (expected_type))
				throw new PlistError.TYPE_MISMATCH ("Property list key '%s' does not have the expected type".printf (key));
			return val;
		}

		protected void set_value (string key, Value val) {
			storage[key] = val;
		}
	}

	public errordomain PlistError {
		INVALID_DATA,
		KEY_NOT_FOUND,
		TYPE_MISMATCH
	}
}
