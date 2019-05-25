rule CRxPicker_start
{
	meta:
		script = "Type.as CRxPicker"
		script = "Type.aanc CRxPicker,CRxObject"
		script = "Type.comment CRxPicker,\"鼠标拾取物品管理 type==0x0d\""
		script = "Type.ad CRxPicker,\"void select(CRxStuff* stuff);\""
	condition:
		true
}

//228 CRxStuff  * a_stuff;
rule CRxPicker_a_stuff
{
	meta:
		script = "$result = [@pattern + 0x2e]"
		script = "Type.am CRxPicker,CRxStuff*,a_stuff,0,$result"
	strings:
		$pattern = { C7 85 [4] 0B 00 00 00 80 3D [4] 00 [6] A1 [4] 89 B5 [4] C7 85 [4] FF FF FF FF 39 B0 }
	condition:
		#pattern == 1
}

//230 uint32_t a_enable;
rule CRxPicker_a_enable
{
	meta:
		script = "$result = [@pattern + 0x37]"
		script = "Type.am CRxPicker,uint32_t,a_enable,0,$result"
	strings:
		$pattern = { f8 03 00 00 [12] 83 ?? 03 [12] 83 ?? 00 [2] 83 ?? 02 [14] 38 }
	condition:
		#pattern == 1
}

rule CRxPicker_end
{
	meta:
		script = "Type.print CRxPicker,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}