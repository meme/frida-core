namespace Frida.Fruity {
	public class Plist : PlistDict {
		public Plist.from_binary (uint8[] data) throws PlistError {
			var parser = new BinaryParser (this);
			parser.parse (data);
		}

		public Plist.from_xml (string xml) throws PlistError {
			var parser = new XmlParser (this);
			parser.parse (xml);
		}

		public string to_xml () {
			var builder = new StringBuilder ();
			var writer = new XmlWriter (builder);
			writer.write_plist (this);
			return builder.str;
		}

		private class BinaryParser : Object {
			public Plist plist {
				get;
				construct;
			}

			private DataInputStream input;

			private uint8 offset_size;
			private uint8 object_ref_size;
			private uint64 offset_table_offset;

			private uint8 object_info;

			private const uint64 MAX_OBJECT_SIZE = 100 * 1024 * 1024;
			private const uint64 MAX_OBJECT_COUNT = 32 * 1024;

			public BinaryParser (Plist plist) {
				Object (plist: plist);
			}

			public void parse (uint8[] data) throws PlistError {
				unowned string magic = (string) data;
				if (!magic.has_prefix ("bplist"))
					throw new PlistError.INVALID_DATA ("Invalid binary plist");

				try {
					input = new DataInputStream (new MemoryInputStream.from_bytes (new Bytes.static (data)));
					input.byte_order = BIG_ENDIAN;

					input.seek (-26, END);
					offset_size = input.read_byte ();
					object_ref_size = input.read_byte ();
					var num_objects = input.read_uint64 ();
					if (num_objects > MAX_OBJECT_COUNT)
						throw new PlistError.INVALID_DATA ("Invalid binary plist: too many objects");
					var top_object_ref = input.read_uint64 ();
					offset_table_offset = input.read_uint64 ();

					printerr ("offset_size=%u\n", (uint) offset_size);
					printerr ("object_ref_size=%u\n", (uint) object_ref_size);
					printerr ("num_objects=%u\n", (uint) num_objects);
					printerr ("top_object_ref=%u\n", (uint) top_object_ref);
					printerr ("offset_table_offset=%u\n", (uint) offset_table_offset);

					var top_object = parse_object (top_object_ref);
				} catch (GLib.Error e) {
					throw new PlistError.INVALID_DATA ("Invalid binary plist: %s", e.message);
				}
			}

			private Value? parse_object (uint64 object_ref) throws GLib.Error {
				seek_to_object (object_ref);

				uint8 marker = input.read_byte ();
				uint8 object_type = (marker & 0xf0) >> 4;
				object_info = marker & 0x0f;

				printerr ("object_type=%u object_info=%u\n", object_type, object_info);
				switch (object_type) {
					case 0xd:
						return parse_dict ();

					default:
						throw new PlistError.INVALID_DATA ("Unsupported object type: 0x%x\n", object_type);
				}

				return null;
			}

			private Value? parse_dict () throws GLib.Error {
			}

			private void seek_to_object (uint64 object_ref) throws GLib.Error {
				input.seek ((int64) (offset_table_offset + (object_ref * offset_size)), SET);

				uint64 offset;
				switch (offset_size) {
					case 1:
						offset = input.read_byte ();
						break;
					case 2:
						offset = input.read_uint16 ();
						break;
					case 4:
						offset = input.read_uint32 ();
						break;
					default:
						throw new PlistError.INVALID_DATA ("Unsupported offset size: %u", offset_size);
				}

				input.seek ((int64) offset, SET);
			}

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

			private Gee.Deque<PartialValue> stack = new Gee.LinkedList<PartialValue> ();

			public XmlParser (Plist plist) {
				Object (plist: plist);
			}

			public void parse (string xml) throws PlistError {
				try {
					var context = new MarkupParseContext (parser, 0, this, null);
					context.parse (xml, -1);
				} catch (MarkupError e) {
					throw new PlistError.INVALID_DATA (e.message);
				}
			}

			private void on_start_element (MarkupParseContext context, string element_name, string[] attribute_names, string[] attribute_values) throws MarkupError {
				var partial = stack.peek_head ();
				if (partial == null) {
					if (element_name == "dict")
						stack.offer_head (new PartialValue.with_dict (plist));
					return;
				}

				switch (partial.need) {
					case DICT_KEY_START:
						if (element_name == "key")
							partial.need = DICT_KEY_TEXT;
						return;

					case DICT_VALUE_START:
						partial.type = element_name;
						partial.val = null;

						if (element_name == "dict") {
							stack.offer_head (new PartialValue.with_dict (new PlistDict ()));
							partial.need = DICT_VALUE_END;
							return;
						}

						if (element_name == "array") {
							stack.offer_head (new PartialValue.with_array (new PlistArray ()));
							partial.need = DICT_VALUE_END;
							return;
						}

						partial.need = DICT_VALUE_TEXT_OR_END;

						return;

					case ARRAY_VALUE_START:
						partial.type = element_name;
						partial.val = null;

						if (element_name == "dict") {
							stack.offer_head (new PartialValue.with_dict (new PlistDict ()));
							partial.need = ARRAY_VALUE_END;
							return;
						}

						if (element_name == "array") {
							stack.offer_head (new PartialValue.with_array (new PlistArray ()));
							partial.need = ARRAY_VALUE_END;
							return;
						}

						partial.need = ARRAY_VALUE_TEXT_OR_END;

						return;
				}
			}

			private void on_end_element (MarkupParseContext context, string element_name) throws MarkupError {
				var partial = stack.peek_head ();
				if (partial == null)
					return;

				switch (partial.need) {
					case DICT_KEY_START:
						if (element_name == "dict") {
							stack.poll_head ();

							var parent = stack.peek_head ();
							if (parent == null)
								return;

							switch (parent.need) {
								case DICT_VALUE_END:
									parent.dict.set_dict (parent.key, partial.dict);
									parent.need = DICT_KEY_START;
									break;

								case ARRAY_VALUE_END:
									parent.array.add_value (partial.dict);
									parent.need = ARRAY_VALUE_START;
									break;
							}
						}

						return;

					case ARRAY_VALUE_START:
						if (element_name == "array") {
							stack.poll_head ();

							var parent = stack.peek_head ();
							if (parent == null)
								return;

							switch (parent.need) {
								case DICT_VALUE_END:
									parent.dict.set_array (parent.key, partial.array);
									parent.need = DICT_KEY_START;
									break;

								case ARRAY_VALUE_END:
									parent.array.add_value (partial.array);
									parent.need = ARRAY_VALUE_START;
									break;
							}
						}

						return;

					case DICT_KEY_END:
						if (element_name == "key")
							partial.need = DICT_VALUE_START;
						return;

					case DICT_VALUE_TEXT_OR_END:
					case DICT_VALUE_END: {
						var val = try_create_value (partial.type, partial.val);
						if (val != null)
							partial.dict.set_value (partial.key, val);
						partial.need = DICT_KEY_START;
						return;
					}

					case ARRAY_VALUE_TEXT_OR_END:
					case ARRAY_VALUE_END: {
						var val = try_create_value (partial.type, partial.val);
						if (val != null)
							partial.array.add_value (val);
						partial.need = ARRAY_VALUE_START;
						return;
					}
				}
			}

			private void on_text (MarkupParseContext context, string text, size_t text_len) throws MarkupError {
				var partial = stack.peek_head ();
				if (partial == null)
					return;

				switch (partial.need) {
					case DICT_KEY_TEXT:
						partial.key = text;
						partial.need = DICT_KEY_END;
						return;

					case DICT_VALUE_TEXT_OR_END:
						partial.val = text;
						partial.need = DICT_VALUE_END;
						return;

					case ARRAY_VALUE_TEXT_OR_END:
						partial.val = text;
						partial.need = ARRAY_VALUE_END;
						return;
				}
			}

			private class PartialValue {
				public enum Need {
					DICT_KEY_START,
					DICT_KEY_TEXT,
					DICT_KEY_END,
					DICT_VALUE_START,
					DICT_VALUE_TEXT_OR_END,
					DICT_VALUE_END,
					ARRAY_VALUE_START,
					ARRAY_VALUE_TEXT_OR_END,
					ARRAY_VALUE_END
				}

				public PlistDict? dict;
				public PlistArray? array;
				public Need need;
				public string? key;
				public string? type;
				public string? val;

				public PartialValue.with_dict (PlistDict dict) {
					this.dict = dict;
					this.need = DICT_KEY_START;
				}

				public PartialValue.with_array (PlistArray array) {
					this.array = array;
					this.need = ARRAY_VALUE_START;
				}
			}

			public Value? try_create_value (string? type, string? val) {
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

			public void write_dict (PlistDict dict) {
				write_line ("<dict>");
				level++;

				var keys = new Gee.ArrayList<string> ();
				foreach (var key in dict.keys)
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

			public void write_array (PlistArray array) {
				write_line ("<array>");
				level++;

				foreach (var val in array.elements)
					write_value (val);

				level--;
				write_line ("</array>");
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
				} else if (type == typeof (PlistDict)) {
					write_dict (val.get_object () as PlistDict);
				} else if (type == typeof (PlistArray)) {
					write_array (val.get_object () as PlistArray);
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

	public class PlistDict : Object {
		public bool is_empty {
			get {
				return storage.is_empty;
			}
		}

		public int size {
			get {
				return storage.size;
			}
		}

		public Gee.Iterable<string> keys {
			owned get {
				return storage.keys;
			}
		}

		public Gee.Iterable<Value?> values {
			owned get {
				return storage.values;
			}
		}

		private Gee.HashMap<string, Value?> storage = new Gee.HashMap<string, Value?> ();

		public void clear () {
			storage.clear ();
		}

		public void remove (string key) {
			storage.unset (key);
		}

		public bool has (string key) {
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

		public unowned string get_string (string key) throws PlistError {
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

		public PlistDict get_dict (string key) throws PlistError {
			return get_value (key, typeof (PlistDict)).get_object () as PlistDict;
		}

		public void set_dict (string key, PlistDict dict) {
			var gval = Value (typeof (PlistDict));
			gval.set_object (dict);
			set_value (key, gval);
		}

		public PlistArray get_array (string key) throws PlistError {
			return get_value (key, typeof (PlistArray)).get_object () as PlistArray;
		}

		public void set_array (string key, PlistArray array) {
			var gval = Value (typeof (PlistArray));
			gval.set_object (array);
			set_value (key, gval);
		}

		public Value get_value (string key, GLib.Type expected_type = GLib.Type.INVALID) throws PlistError {
			var val = storage[key];
			if (val == null)
				throw new PlistError.KEY_NOT_FOUND ("Key '%s' does not exist".printf (key));
			if (expected_type != Type.INVALID && !val.holds (expected_type))
				throw new PlistError.TYPE_MISMATCH ("Key '%s' does not have the expected type".printf (key));
			return val;
		}

		public void set_value (string key, Value val) {
			storage[key] = val;
		}
	}

	public class PlistArray : Object {
		public bool is_empty {
			get {
				return storage.is_empty;
			}
		}

		public int length {
			get {
				return storage.size;
			}
		}

		public Gee.Iterable<Value?> elements {
			get {
				return storage;
			}
		}

		private Gee.ArrayList<Value?> storage = new Gee.ArrayList<Value?> ();

		public void clear () {
			storage.clear ();
		}

		public void remove_at (int index) {
			storage.remove_at (index);
		}

		public bool get_boolean (int index) throws PlistError {
			return get_value (index, typeof (bool)).get_boolean ();
		}

		public void add_boolean (bool val) {
			var gval = Value (typeof (bool));
			gval.set_boolean (val);
			add_value (gval);
		}

		public int get_int (int index) throws PlistError {
			return get_value (index, typeof (int)).get_int ();
		}

		public void add_int (int val) {
			var gval = Value (typeof (int));
			gval.set_int (val);
			add_value (gval);
		}

		public uint get_uint (int index) throws PlistError {
			return get_value (index, typeof (uint)).get_uint ();
		}

		public void add_uint (uint val) {
			var gval = Value (typeof (uint));
			gval.set_uint (val);
			add_value (gval);
		}

		public unowned string get_string (int index) throws PlistError {
			return get_value (index, typeof (string)).get_string ();
		}

		public void add_string (string str) {
			var gval = Value (typeof (string));
			gval.set_string (str);
			add_value (gval);
		}

		public unowned Bytes get_bytes (int index) throws PlistError {
			return (Bytes) get_value (index, typeof (Bytes)).get_boxed ();
		}

		public string get_bytes_as_string (int index) throws PlistError {
			var bytes = get_bytes (index);
			unowned string unterminated_str = (string) bytes.get_data ();
			return unterminated_str[0:bytes.length];
		}

		public void add_bytes (Bytes val) {
			var gval = Value (typeof (Bytes));
			gval.set_boxed (val);
			add_value (gval);
		}

		public PlistDict get_dict (int index) throws PlistError {
			return get_value (index, typeof (PlistDict)).get_object () as PlistDict;
		}

		public void add_dict (PlistDict dict) {
			var gval = Value (typeof (PlistDict));
			gval.set_object (dict);
			add_value (gval);
		}

		public PlistArray get_array (int index) throws PlistError {
			return get_value (index, typeof (PlistArray)).get_object () as PlistArray;
		}

		public void add_array (PlistArray array) {
			var gval = Value (typeof (PlistArray));
			gval.set_object (array);
			add_value (gval);
		}

		public Value get_value (int index, GLib.Type expected_type = GLib.Type.INVALID) throws PlistError {
			var val = storage[index];
			if (expected_type != Type.INVALID && !val.holds (expected_type))
				throw new PlistError.TYPE_MISMATCH ("Array element does not have the expected type");
			return val;
		}

		public void add_value (Value val) {
			storage.add (val);
		}
	}

	public errordomain PlistError {
		INVALID_DATA,
		KEY_NOT_FOUND,
		INVALID_INDEX,
		TYPE_MISMATCH
	}
}
