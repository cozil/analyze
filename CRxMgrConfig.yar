rule CRxMgrConfig_start
{
	meta:
		script = "Type.as CRxMgrConfig"
		script = "Type.aanc CRxMgrConfig,CRxMgr"
		script = "Type.comment CRxMgrConfig,\"游戏设定窗口管理器\""
		script = "Type.ad CRxMgrConfig,\"inline void switch_role_ui() {{ switch_role = 1; }}\""
	condition:
		true
}

//228 uint32_t switch_role;
rule CRxMgrConfig_switch_role
{
	meta:
		script = "$result = [@pattern + 0x08]"
		script = "Type.am CRxMgrConfig,uint32_t,switch_role,0,$result"
		script = "Type.mcomment CRxMgrConfig,switch_role,\"设置为1可以立即小退\""
	strings:
		$pattern = { FF 15 [4] 8B 8B [4] 8B F0 85 C9 0F 84 [4] 8B C1 2B C6 99 33 C2 2B C2 3D 70 17 00 00 0F 8E}
	condition:
		#pattern == 1
}

rule CRxMgrConfig_end
{
	meta:
		script = "Type.print CRxMgrConfig,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}

