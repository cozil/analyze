rule CRxMgrMyShop_start
{
	meta:
		script = "Type.as CRxMgrMyShop"
		script = "Type.aanc CRxMgrMyShop,CRxMgr"
		script = "Type.ad CRxMgrMyShop,\"inline void click_playershop_buy(int id) {{ click(0x50+i); }} //id:[0,7]\""
		script = "Type.ad CRxMgrMyShop,\"inline void click_playershop_close() {{ click(0x63); }}\""
		
	condition:
		true
}

//CRxWnd * dlg_myshop;
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

//rule CRxMgrMyShop_myshop_ctrls
//{
//	meta:
//		script = "$result = [@pattern +0xe]"
//		script = "$result1 = 0x100 - byte:[@pattern + 0x4f]"
//		script = "Type.am CRxMgrMyShop,CRxLabel*,dlg_lb_names,8,$result-$result1"
//		script = "Type.am CRxMgrMyShop,CRxLabel*,dlg_lb_prices,8,$result"
//		script = "Type.am CRxMgrMyShop,CRxLabel*,dlg_lb_counts,8,$result+$result1"
//	strings:
//		$pattern = { 6A 01 E8 [4] BB 42 00 00 00 8D BE [4] EB ?? 8D 49 00 68 7C 03 00 00 E8 [25] 6A 12 68 82 00 00 00 6A 05 53 6A 43 8B C8 E8 [4] EB ?? 33 C0 89 47 }
//	condition:
//		#pattern == 1
//}

//CRxWnd * dlg_playershop;
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

//rule CRxMgrMyShop_playershop_ctrls
//{
//	meta:
//		script = "$result = [@pattern + 0x7]"
//		script = "$result1 = 0x100 - byte:[@pattern + 0x44]"
//		script = "Type.am CRxMgrMyShop,CRxLabel*,dlg1_lb_names,8,$result-$result1"
//		script = "Type.am CRxMgrMyShop,CRxLabel*,dlg1_lb_prices,8,$result"
//		script = "Type.am CRxMgrMyShop,CRxLabel*,dlg1_lb_counts,8,$result+$result1"
//		script = "Type.am CRxMgrMyShop,CRxButton*,dlg1_bn_buys,8,$result+$result1*2"
//	strings:
//		$pattern = { BB 42 00 00 00 8D BE [4] 90 68 7C 03 00 00 E8 [25] 6A 12 68 82 00 00 00 6A 05 53 6A 43 8B C8 E8 [4] EB [3] 89 47 }
//	condition:
//		#pattern == 1
//}

//rule CRxMgrMyShop_dlg1_bn_close
//{
//	meta:
//		script = "$result = [@pattern + 0x28]"
//		script = "Type.am CRxMgrMyShop,CRxButton*,dlg1_bn_close,0,$result"
//	strings:
//		$pattern = { 6A 63 [3] AE 01 00 00 [3] 4C [2] AE 01 00 00 ?? 4C [2] E8 [14] 89 86 }
//	condition:
//		#pattern == 1
//}

//RX_SHOP_ITEM items[8];
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