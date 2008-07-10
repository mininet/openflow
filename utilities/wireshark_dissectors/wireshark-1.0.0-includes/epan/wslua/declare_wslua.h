/* This file is automatically genrated by make-reg.pl do not edit */

#define WSLUA_DECLARE_CLASSES() \
	WSLUA_CLASS_DECLARE(ByteArray);\
	WSLUA_CLASS_DECLARE(Tvb);\
	WSLUA_CLASS_DECLARE(TvbRange);\
	WSLUA_CLASS_DECLARE(Pref);\
	WSLUA_CLASS_DECLARE(Prefs);\
	WSLUA_CLASS_DECLARE(ProtoField);\
	WSLUA_CLASS_DECLARE(Proto);\
	WSLUA_CLASS_DECLARE(Dissector);\
	WSLUA_CLASS_DECLARE(DissectorTable);\
	WSLUA_CLASS_DECLARE(TreeItem);\
	WSLUA_CLASS_DECLARE(Address);\
	WSLUA_CLASS_DECLARE(Column);\
	WSLUA_CLASS_DECLARE(Columns);\
	WSLUA_CLASS_DECLARE(Pinfo);\
	WSLUA_CLASS_DECLARE(Listener);\
	WSLUA_CLASS_DECLARE(TextWindow);\
	WSLUA_CLASS_DECLARE(Dir);\
	WSLUA_CLASS_DECLARE(FieldInfo);\
	WSLUA_CLASS_DECLARE(Field);\
	WSLUA_CLASS_DECLARE(PseudoHeader);\
	WSLUA_CLASS_DECLARE(Dumper);\


#define WSLUA_DECLARE_FUNCTIONS() \
	WSLUA_FUNCTION wslua_register_postdissector(lua_State* L);\
	WSLUA_FUNCTION wslua_gui_enabled(lua_State* L);\
	WSLUA_FUNCTION wslua_register_menu(lua_State* L);\
	WSLUA_FUNCTION wslua_new_dialog(lua_State* L);\
	WSLUA_FUNCTION wslua_retap_packets(lua_State* L);\
	WSLUA_FUNCTION wslua_copy_to_clipboard(lua_State* L);\
	WSLUA_FUNCTION wslua_open_capture_file(lua_State* L);\
	WSLUA_FUNCTION wslua_set_filter(lua_State* L);\
	WSLUA_FUNCTION wslua_apply_filter(lua_State* L);\
	WSLUA_FUNCTION wslua_reload(lua_State* L);\
	WSLUA_FUNCTION wslua_browser_open_url(lua_State* L);\
	WSLUA_FUNCTION wslua_browser_open_data_file(lua_State* L);\
	WSLUA_FUNCTION wslua_format_date(lua_State* L);\
	WSLUA_FUNCTION wslua_format_time(lua_State* L);\
	WSLUA_FUNCTION wslua_report_failure(lua_State* L);\
	WSLUA_FUNCTION wslua_critical(lua_State* L);\
	WSLUA_FUNCTION wslua_warn(lua_State* L);\
	WSLUA_FUNCTION wslua_message(lua_State* L);\
	WSLUA_FUNCTION wslua_info(lua_State* L);\
	WSLUA_FUNCTION wslua_debug(lua_State* L);\
	WSLUA_FUNCTION wslua_loadfile(lua_State* L);\
	WSLUA_FUNCTION wslua_dofile(lua_State* L);\
	WSLUA_FUNCTION wslua_persconffile_path(lua_State* L);\
	WSLUA_FUNCTION wslua_datafile_path(lua_State* L);\
	WSLUA_FUNCTION wslua_register_stat_cmd_arg(lua_State* L);\
	WSLUA_FUNCTION wslua_all_field_infos(lua_State* L);\


extern void wslua_register_classes(lua_State* L);
extern void wslua_register_functions(lua_State* L);


