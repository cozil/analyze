/*
CRxMgrState中的成员dlg_qi指向角色气功点数分配窗口，该窗口的背景图片：
..\\datas\\interface\\DATA\\window_character\\window_character_passiveskill.bmp

通过对该字符串地址的引用，可以找到创建窗口的位置。
*/


rule CRxMgrState_start
{
	meta:
		script = "Type.as CRxMgrState"
		script = "Type.aanc CRxMgrState,CRxMgr"
		script = "Type.comment CRxMgrState, \"人物信息窗口管理器 基本信息/武功/气功/动作\""
		//script = "Type.as RX_QI_PAIR"
		//script = "Type.am RX_QI_PAIR,CRxButton*,bn_add"
		//script = "Type.am RX_QI_PAIR,CRxLabel*,lb_value"
	condition:
		true
}


//24c CRxCombo * cmb_wxname;
rule CRxMgrState_cmb_wxname
{
	meta:
		script = "$result = [@pattern + 0x1e]"
		script = "Type.am CRxMgrState,CRxCombo*,cmb_wxname,0,$result"
		script = "Type.mcomment CRxMgrState, cmb_wxname,\"武勋称号下拉框\""
		script = "$result = @pattern + 0x12 + [@pattern + 0x0e]"
		script = "lblset $result, CRxCombo::create"
	strings:
		$pattern = { 6A 11 68 B9 00 00 00 6A 23 6A 64 8B C8 E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//31c CRxWnd * dlg_qi;
rule CRxMgrState_dlg_qi
{
	meta:
		script = "$result = [@pattern + 0x15]"
		script = "Type.am CRxMgrState,CRxWnd*,dlg_qi,0,$result"
		script = "Type.mcomment CRxMgrState,dlg_qi,\"气功设置窗口\""
	strings:
		$pattern = { 6A 03 56 51 8B 88 [4] 52 E8 [4] 50 6A 78 89 86 [4] E8 }
	condition:
		#pattern == 1
}


//320 CRxLabel * qi_lb_point;
rule CRxMgrState_qi_lb_point
{
	meta:
		script = "$result = [@pattern + 0x26]"
		script = "Type.am CRxMgrState,CRxLabel*,qi_lb_point,0,$result"
	strings:
		$pattern = { 6A 0F 6A 3A 6A 05 6A 16 6A 34 [2] E8 [8] 8B 8E [6] C7 45 ?? FF FF FF FF 89 86 }
	condition:
		#pattern == 1
}

//3A4 CRxList * qi_ls_qigong1;
rule CRxMgrState_qi_ls_qigong1
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxMgrState,CRxList*,qi_ls_qigong1,0,$result"
	strings:
		$pattern = { C7 [2] 01 00 00 00 [4] 68 [5] 6A 10 6A 03 [2] E8 [8] 8B [5] 89 }
	condition:
		#pattern == 1
}

//324 CRxLabel * qi_lb_values[0x10];
//3AC CRxButton * qi_bn_adds[0x10];
rule CRxMgrState_qi_items1
{
	meta:
		script = "$result = [@pattern + 0x1c]"
		script = "Type.am CRxMgrState,CRxButton*,qi_bn_adds,0x10,$result"
		script = "$result += [@pattern1 + 0x36]"
		script = "Type.am CRxMgrState,CRxLabel*,qi_lb_values,0x10,$result"
	strings:
		$pattern = { 6A 00 E8 [4] 8B 8E [5] 6A 78 E8 [4] 83 C4 08 [2] 8D [5] 68 F0 03 00 00 E8 [4] 83 C4 04 [6] C7 [2] 02 00 00 00 }
		$pattern1 = { C7 [2] 03 00 00 00 [19] 6A 0D 6A 0F 6A 05 [2] 24 [3] 10 [3] E8 [9] 89 }
	condition:
		for all of them : (# == 1)
}

//3A8 CRxList * qi_ls_qigong2;
rule CRxMgrState_qi_ls_qigong2
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxMgrState,CRxList*,qi_ls_qigong2,0,$result"
	strings:
		$pattern = { C7 [2] 04 00 00 00 [4] 68 [5] 6A 10 6A 04 [2] E8 [8] 8B [5] 89 }
	condition:
		#pattern == 1
}

//504 char modified;
rule CRxMgrState_modified
{
	meta:
		script = "$result = [@pattern + 0x23]"
		script = "Type.am CRxMgrState,char,modified,0,$result"
		script = "Type.mcomment CRxMgrState,modified,\"此处特征码末尾是CRxCombo::current_index的偏移:{p:[@pattern + 0x29]}\""
	strings:
		$pattern = { C7 85 [4] C7 E1 14 3C C7 85 [4] 00 00 00 00 E8 [4] EB ?? 8B 86 [4] 88 9E [4] 8B 88 }
	condition:
		#pattern == 1
}

rule CRxMgrState_end
{
	meta:
		script = "Type.print CRxMgrState,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}