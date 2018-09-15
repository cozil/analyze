/*
CRxMgrState中的成员dlg_qi指向角色气功点数分配窗口，该窗口的背景图片：
..\\datas\\interface\\DATA\\window_character\\window_character_passiveskill.bmp

通过对该字符串地址的引用，可以找到创建窗口的位置。
*/


rule CRxMgrState_start
{
	meta:
		script = "log \"struct CRxMgrState {\""
	condition:
		true
}


//24c CRxCombo * cmb_wxname;
rule CRxMgrState_cmb_wxname
{
	meta:
		script = "$result = [@pattern + 0x1e]"
		script = "log \"//武勋称号下拉框\""
		script = "log \"/*{p:$result}*/    CRxCombo * cmb_wxname;\""
		script = "$result = @pattern + 0x12 + [@pattern + 0x0e]"
		script = "lblset $result, CRxCombo::create"
	strings:
		$pattern = { 6A 11 68 B9 00 00 00 6A 23 6A 64 8B C8 E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//31c CRxWndQi * dlg_qi;
rule CRxMgrState_dlg_qi
{
	meta:
		script = "$result = [@pattern + 0x15]"
		script = "log \"//气功设置窗口\""
		script = "log \"/*{p:$result}*/    CRxWndQi * dlg_qi;\""
	strings:
		$pattern = {6A 03 56 51 8B 88 [4] 52 E8 [4] 50 6A 78 89 86 [4] E8 }
	condition:
		#pattern == 1
}

//504 char modified;
rule CRxMgrState_modified
{
	meta:
		script = "$result = [@pattern + 0x23]"
		script = "log \"//此处特征码末尾是CRxCombo::current_index的偏移:{p:[@pattern + 0x29]}\""
		script = "log \"/*{p:$result}*/    char modified;\""
	strings:
		$pattern = { C7 85 [4] C7 E1 14 3C C7 85 [4] 00 00 00 00 E8 [4] EB ?? 8B 86 [4] 88 9E [4] 8B 88 }
	condition:
		#pattern == 1
}



rule CRxMgrState_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}