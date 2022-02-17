# 0CD - Quality of life utlities for obsessive compulsive CTF enthusiasts
# by b0bb (https://twitter.com/0xb0bb) 

from binaryninja import PluginCommand, Settings
from .modules import stackguards

settings = Settings()
settings.register_group("0cd", "0CD")

settings.register_setting("0cd.stackguards.var_name", """
	{
		"title" : "Stack canary variable name",
		"type" : "string",
		"default" : "CANARY",
		"description" : "Name of the stack canary stored on the stack."
	}
""")

settings.register_setting("0cd.stackguards.tcb_name", """
	{
		"title" : "TCB variable name",
		"type" : "string",
		"default" : "tcb",
		"description" : "Name of the tcp struct pointer stored on the stack."
	}
""")

PluginCommand.register(
	"0CD\Stack Guards\Clean all",
	"Clean up stack guards in all functions",
	stackguards.run_plugin_all
)

PluginCommand.register_for_function(
	"0CD\Stack Guards\Clean current function",
	"Clean up stack guards in the current function",
	stackguards.run_plugin_current
)
