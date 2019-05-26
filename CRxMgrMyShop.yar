rule CRxMgrMyShop_start
{
	meta:
		script = "Type.as CRxMgrMyShop"
		script = "Type.aanc CRxMgrMyShop,CRxMgr"
		script = "Type.ad CRxMgrMyShop,\"static const int playershop_buy_id = 0x50;\""
		script = "Type.ad CRxMgrMyShop,\"static const int playershop_close_id = 0x63;\""
		script = "Type.ad CRxMgrMyShop,\"inline void click_playershop_buy(int id) {{ click(playershop_buy_id+id); }} //id:[0,7]\""
	condition:
		true
}

//2c4 CRxWnd * dlg_myshop;
rule CRxMgrMyShop_dlg_myshop
{
	meta:
		script = "$result = [@pattern + 0x26]"
		script = "Type.am CRxMgrMyShop,CRxWnd*,dlg_myshop,0,$result"
		script = "Type.mcomment CRxMgrMyShop,dlg_myshop,\"自己开店商店窗口\""
	strings:
		$pattern = { 6A 01 56 68 [4] 68 [4] 57 51 8B C8 E8 [4] EB ?? 33 C0 50 6A 78 C7 45 ?? FF FF FF FF 89 86 }
	condition:
		#pattern == 1	
}

//340 CRxWnd * dlg_playershop;
rule CRxMgrMyShop_dlg_playershop
{
	meta:
		script = "$result = [@pattern + 0x23]"
		script = "Type.am CRxMgrMyShop,CRxWnd*,dlg_playershop,0,$result"
		script = "Type.mcomment CRxMgrMyShop,dlg_playershop,\"进入别人商店窗口\""
	strings:
		$pattern = { 6A 01 6A 01 56 68 [4] 51 52 8B C8 E8 [4] EB ?? 33 C0 50 6A 78 C7 45 ?? FF FF FF FF 89 86 }
	condition:
		#pattern == 1
}

//40c RX_SHOP_ITEM items[8];
rule CRxMgrMyShop_items
{
	meta:
		script = "$result = [@pattern + 0x15]"
		script = "Type.am CRxMgrMyShop,RX_SHOP_ITEM,items,8,$result"
	strings:
		$pattern = { 40 83 C1 ?? 83 F8 08 7C ?? 5F 5E 5D C2 04 00 6B C0 ?? 8D BC 38 [4] B9 [4] F3 A5 }
	condition:
		#pattern == 1
}

rule CRxMgrMyShop_end
{
	meta:
		script = "Type.print CRxMgrMyShop,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}