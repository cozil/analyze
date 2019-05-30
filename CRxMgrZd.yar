rule CRxMgrZd_start
{
	meta:
		script = "Type.as CRxMgrZd"
		script = "Type.aanc CRxMgrZd,CRxMgr"
		script = "Type.comment CRxMgrZd,\"真斗烈战管理"
		script = "Type.ad CRxMgrZd,\"static const int goback_id = 0xc8;\""
		script = "Type.ad CRxMgrZd,\"inline void click_goback() {{ click(goback_id); }}\""
	condition:
		true
}

//390 CRxWnd * dlg_goback;
rule CRxMgrZd_dlg_goback
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrZd,CRxWnd*,dlg_goback,0,$result"
	strings:	
		//指向CRxMgrZd的构造函数
		//查看对ZdMgr赋值的引用，即可找到构造函数
		//构造dlg_goback窗口时引用了窗口图片：
		//..\\datas\\interface\\DATA\\etc\\forcewar_Move_Village_button_none.bmp
		
		$pattern = { 89 86 [4] E8 [4] D9 EE 8B 8E [4] D9 95 [4] 8B 85 [4] D9 9D [4] 8B 95 [4] 53 53 68 C8 00 00 00 68 [4] 68 [4] 53 52 50 51 56 E8 [4] 89 86 [4] 8B 15 [4]D1 EA 81 EA 90 01 00 00}
	condition:
		#pattern == 1
}

rule CRxMgrZd_end
{
	meta:
		script = "Type.print CRxMgrZd,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}