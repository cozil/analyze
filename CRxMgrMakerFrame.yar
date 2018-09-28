rule CRxMgrMakerFrame_start
{
	meta:
		script = "Type.as CRxMgrMakerFrame"
		script = "Type.aanc CRxMgrMakerFrame,CRxMgr"
		script = "Type.comment CRxMgrMakerFrame,\"制造框架窗口管理\""
	condition:
		true
}

//CRxWnd * dlg;
rule CRxMgrMakerFrame_dlg
{
	meta:
		script = "$result = [@pattern + 0x8]"
		script = "Type.am CRxMgrMakerFrame,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { D9 05 [4] 8B 96 [4] D9 5D ?? D9 05 [4] 8B 4D ?? 6A 00 D9 5D ?? 8B 45 ?? 6A 00 68 98 08 00 00 }
	condition:
		#pattern == 1
}

//CRxButton * dlg_bn_make_smith;
rule CRxMgrMakerFrame_dlg_bn_make_smith
{
	meta:
		script = "$result = [@pattern + 0x1a]"
		script = "Type.am CRxMgrMakerFrame,CRxButton*,dlg_bn_make_smith,0,$result"
		script = "Type.mcomment CRxMgrMakerFrame,dlg_bn_make_smith, \"打开武器制造窗口\""
	strings:
		$pattern = { 6A 00 D9 5D ?? 6A 00 68 99 08 00 00 68 [4] 68 [4] 6A 00 89 86 }
	condition:
		#pattern == 1
}

//CRxButton * dlg_bn_make_sewer;
rule CRxMgrMakerFrame_dlg_bn_make_sewer
{
	meta:
		script = "$result = [@pattern + 0x17]"
		script = "Type.am CRxMgrMakerFrame,CRxButton*,dlg_bn_make_sewer,0,$result"
		script = "Type.mcomment CRxMgrMakerFrame,dlg_bn_make_sewer, \"打开防具制造窗口\""
	strings:
		$pattern = { 6A 00 6A 00 68 9A 08 00 00 68 [4] 68 [4] 6A 00 89 86 }
	condition:
		#pattern == 1
}

//CRxButton * dlg_bn_make_chemist;
rule CRxMgrMakerFrame_dlg_bn_make_chemist
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrMakerFrame,CRxButton*,dlg_bn_make_chemist,0,$result"
		script = "Type.mcomment CRxMgrMakerFrame,dlg_bn_make_chemist, \"打开爆毒制造窗口\""
	strings:
		$pattern = { 89 86 [4] D9 05 [4] 8B 4D ?? 8B 96 [4] D9 5D ?? 8B 45 ?? 6A 00 6A 00 68 9B 08 00 00 }
	condition:
		#pattern == 1
}

//CRxButton * dlg_bn_break;
rule CRxMgrMakerFrame_dlg_bn_break
{
	meta:
		script = "$result = [@pattern + 0x2e]"
		script = "Type.am CRxMgrMakerFrame,CRxButton*,dlg_bn_break,0,$result"
		script = "Type.mcomment CRxMgrMakerFrame,dlg_bn_break, \"打开分解窗口\""
	strings:
		$pattern = { 6A 00 6A 00 68 9B 08 00 00 68 [4] 68 [4] 6A 00 [4] E8 [4] 8B 8E [4] 83 C4 50 68 [4] 89 86 }
	condition:
		#pattern == 1
}

//CRxButton * dlg_bn_close;
rule CRxMgrMakerFrame_dlg_bn_close
{
	meta:
		script = "$result = [@pattern + 0xa2]"
		script = "Type.am CRxMgrMakerFrame,CRxButton*,dlg_bn_close,0,$result"
		script = "Type.mcomment CRxMgrMakerFrame,dlg_bn_close, \"关闭框架窗口\""
	strings:
		$pattern = { 6A 00 6A 00 68  9b 08 00 00 [118] 6A 00 D9 5D ?? 8B 45 ?? 6A 00 6A 61 68 [4] 68 [4] 6A 00 [4] E8 [4] 89 86 }
	condition:
		#pattern == 1
}

rule CRxMgrMakerFrame_end
{
	meta:
		script = "Type.print CRxMgrMakerFrame,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
