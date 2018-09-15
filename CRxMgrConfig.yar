rule CRxMgrConfig_start
{
	meta:
		script = "log \"struct CRxMgrConfig {\""
	condition:
		true
}

//230 UINT switch_role_ui_time;
rule CRxMgrConfig_switch_role_ui_time
{
	meta:
		script = "$result = [@pattern + 0x08]"
		script = "log \"/*{p:$result}*/    UINT switch_role_ui_time;\""
	strings:
		$pattern = { FF 15 [4] 8B 8B [4] 8B F0 85 C9 0F 84 [4] 8B C1 2B C6 99 33 C2 2B C2 3D 70 17 00 00 0F 8E}
	condition:
		#pattern == 1
}

rule CRxMgrConfig_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}

