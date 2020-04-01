rule CRxCombo_start
{
	meta:
		script = "Type.as CRxCombo"
		script = "Type.aanc CRxCombo,CRxCtrl"
		script = "Type.comment CRxCombo,\"游戏组合框控件 Type=0x11\""
		script = "Type.as RX_CBITEM"
		script = "Type.comment RX_CBITEM,\"CRxCombo类的列表项结构(static)\""
		script = "Type.am RX_CBITEM,char,text,0x64"
		script = "Type.am RX_CBITEM,uint8_t,visible"
		script = "Type.am RX_CBITEM,uint8_t,enable"
		script = "Type.ad CRxCombo,\"inline void select_index(int id) {{ current_index = id; }}\""
		script = "Type.ad CRxCombo,\"bool check_index(int id) const;\""
		script = "Type.ad CRxCombo,\"int find_text(const char * text, bool check_state = true) const;\""
	condition:
		true
}

//230 RX_CBITEM items[0x14];
//a28 int current_index;
rule CRxCombo_members
{
	meta:
		script = "$result = [@pattern + 0x6]"
		script = "Type.am CRxCombo,RX_CBITEM,items,0x14,$result"
		script = "$result = [@pattern + 0x18]"
		script = "Type.am CRxCombo,int,current_index,0,$result"
	strings:
		$pattern = { 6B D2 66 80 BC 32 [4] 00 0F 84 [4] 3B C8 7C ?? 48 89 86 }
	condition:
		#pattern == 1
}

rule CRxCombo_end
{
	meta:
		script = "Type.print RX_CBITEM,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "Type.print CRxCombo,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}