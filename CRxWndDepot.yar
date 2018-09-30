rule CRxWndDepot_start
{
	meta:
		script = "Type.as CRxWndDepot"
		script = "Type.aanc CRxWndDepot,CRxWnd"
		script = "Type.comment CRxWndDepot,\"仓库窗口\""
	condition:
		true
}

rule CRxWndDepot_btns
{
	meta:
		script = "$result = [@pattern + 0x3]"
		script = "Type.am CRxWndDepot,CRxButton*,bn_depot1,0,$result + 4"
		script = "Type.am CRxWndDepot,CRxButton*,bn_depot2,0,$result + 8"
	strings:
		$pattern = { 8D B4 B7 [4] 89 06 C6 80 [4] 00 EB ?? 8B 75 ?? C7 45 ?? 01 00 00 00 85 C0 }
		$pattern1 = { 53 6A 50 6A 61 6A 3D 6A 1C 6A 01 E8 [10] 53 6A 50 68 AA 00 00 00 6A 3D 6A 65 6A 02 E8 }
	condition:
		for all of them : (# == 1)
}

rule CRxWndDepot_end
{
	meta:
		script = "Type.print CRxWndDepot,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}

