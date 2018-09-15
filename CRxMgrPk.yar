
//
//CRxMgrPk部分成员偏移分析
//

rule CRxMgrPk_start
{
	meta:
		script = "log \"struct CRxMgrPk {\""
	condition:
		true
}

//22C short pk_state;
//240 CRxWndPkQuery * dlg_pkquery;
rule CRxMgrPk_dlg_pkquery
{
	meta:
		script = "$result = [@pattern + 0x2c]"
		script = "log \"/*{p:$result}*/    short pk_state;\""
		script = "$result = [@pattern + 0x18]"
		script = "log \"/*{p:$result}*/    CRxWndPkQuery * dlg_pkquery;\""
	strings:
		$pattern = { 0F B6 80 [4] 53 FF 24 85 [4] 8A 5D ?? 0F B6 CB 51 8B 8E [4] E8 [4] 0F B6 D3 F7 DA 1B D2 23 D7 89 96 [4] 84 DB 0F 84 [4] FF 15 }
	condition:
		#pattern == 1		
}

//5bc int battle_start;
rule CRxMgrPk_battle_start
{
	meta:
		script = "$result = [@pattern + 0x30]"
		script = "log \"/*{p:$result}*/    int battle_start;\""
	strings:
		$pattern = { 83 FA 62 77 ?? 6A 01 6A 01 8B CE E8 [4] E9 [4] 3D 41 9C 00 00 0F 85 [4] 6A 01 8B CE E8 [4] E9 [4] 39 BE [4] 74 ?? E8 }
	condition:
		#pattern == 1		
}

//A80 char score_flag;
rule CRxMgrPk_score_flag
{
	meta:
		script = "$result = [@pattern + 0x1a]"
		script = "log \"/*{p:$result}*/    char score_flag;\""
	strings:
		$pattern = { C6 86 [4] 00 C7 05 [4] 00 00 00 00 8B CE E8 [4] 80 BE [4] 00 74 ?? FF D3 2B 86 [4] 3D 88 13 00 00 }
	condition:
		#pattern == 1
}

rule CRxMgrPk_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}