
//
//CRxSelf部分成员偏移分析
//


rule CRxSelf_start
{
	meta:
		script = "log \"struct CRxSelf {\""
	condition:
		true
}

//2cee wx_quota
//2cf0 wx_lose

rule CRxSelf_wx_quota
{
	meta:
		script = "$result = [@pattern + 0x02] - RoleInfo"
		script = "log \"/*{p:$result}*/    short wx_quota;\""
		script = "$result = [@pattern + 0x10] - RoleInfo"
		script = "log \"/*{p:$result}*/    short wx_lose;\""		
	strings:
		$pattern = { 66 A3 [4] 0F B7 8B [4] 66 89 0D [4] 0F B7 93 [4] 66 89 15 [4] 0F B7 83 [4] 66 A3 [4] E8 }
	condition:
		#pattern == 1			
}

//2d04 mnz_zl
//2d08 mnz_zl_max

rule CRxSelf_mnz_zl
{
	meta:
		script = "$result = [@pattern + 0x22] - RoleInfo"
		script = "log \"/*{p:$result}*/    int mnz_zl;\""
		script = "$result = [@pattern + 0x19] - RoleInfo"
		script = "log \"/*{p:$result}*/    int mnz_zl_max;\""		
	strings:
		$pattern = { 83 3D [4] 11 56 57 8B F1 75 ?? 8B 8E [4] 85 C9 74 ?? 8B 3D [4] 85 FF 74 ?? A1 [4] 6B C0 64 99 F7 FF 50 E8 }
	condition:
		#pattern == 1	
}

rule CRxSelf_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}
