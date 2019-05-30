rule CRxMgrList_start
{
	meta:
		script = "Type.as CRxMgrList"
		script = "Type.aanc CRxMgrList,CRxMgr"
		script = "Type.as SlotState"
		script = "Type.am SlotState,char,enabled"
		script = "Type.am SlotState,char,pad_01,0x23"
		
		script = "Type.ad CRxMgrList, \"static const int price_confirm_id = 0x60;      //NPC商店购买物品输入数量确认/取消\""
		script = "Type.ad CRxMgrList, \"static const int price_cancel_id = 0x61;\""
		
		script = "Type.ad CRxMgrList,\"static const int input_confirm_id = 0x62;      //仓库取物品输入数量确认/取消\""
		script = "Type.ad CRxMgrList,\"static const int input_cancel_id = 0x63;\""		
	
		script = "Type.ad CRxMgrList,\"static const int myshop_confirm_id = 0x5a;      //开店输入数量确认/取消\""
		script = "Type.ad CRxMgrList,\"static const int myshop_cancel_id = 0x5b;\""	
		
		script = "Type.ad CRxMgrList,\"static const int drop_confirm_id = 0x5c;      //扔掉属性物品确认/取消\""
		script = "Type.ad CRxMgrList,\"static const int drop_cancel_id = 0x5d;\""	
			
		script = "Type.ad CRxMgrList,\"static const int sell_confirm_id = 0x5e;      //属性物品卖店确认/取消\""
		script = "Type.ad CRxMgrList,\"static const int sell_cancel_id = 0x5f;\""
		
		script = "Type.ad CRxMgrList,\"static const int flyring_confirm_id = 0xc9;      //戒指传送确认/取消\""
		script = "Type.ad CRxMgrList,\"static const int flyring_cancel_id = 0xca;\""	
		
		script = "Type.ad CRxMgrList,\"static const int break_confirm_id = 0xcb;      //属性物品分解确认/取消\""
		script = "Type.ad CRxMgrList,\"static const int break_cancel_id = 0xcc;\""
		
		
		script = "Type.ad CRxMgrList,\"inline void click_price_confirm() {{ click(price_confirm_id); }}\""
		script = "Type.ad CRxMgrList,\"inline void click_price_cancel() {{ click(price_cancel_id); }}\""
		
		script = "Type.ad CRxMgrList,\"inline void click_input_confirm() {{ click(input_confirm_id); }}\""
		script = "Type.ad CRxMgrList,\"inline void click_input_cancel() {{ click(input_cancel_id); }}\""
		
		script = "Type.ad CRxMgrList,\"inline void click_myshop_confirm() {{ click(myshop_confirm_id); }}\""
		script = "Type.ad CRxMgrList,\"inline void click_myshop_cancel() {{ click(myshop_cancel_id); }}\""
		
		script = "Type.ad CRxMgrList,\"inline void click_drop_confirm() {{ click(drop_confirm_id); }}\""
		script = "Type.ad CRxMgrList,\"inline void click_drop_cancel() {{ click(drop_cancel_id); }}\""

		script = "Type.ad CRxMgrList,\"inline void click_sell_confirm() {{ click(sell_confirm_id); }}\""
		script = "Type.ad CRxMgrList,\"inline void click_sell_cancel() {{ click(sell_cancel_id); }}\""
		
		script = "Type.ad CRxMgrList,\"inline void click_flyring_confirm() {{ click(flyring_confirm_id); }}\""
		script = "Type.ad CRxMgrList,\"inline void click_flyring_cancel() {{ click(flyring_cancel_id); }}\""

		script = "Type.ad CRxMgrList,\"inline void click_break_confirm() {{ click(break_confirm_id); }}\""
		script = "Type.ad CRxMgrList,\"inline void click_break_cancel() {{ click(break_cancel_id); }}\""		
			
		script = "Type.ad CRxMgrList,\"int calc_free_space() const;\""
		script = "Type.ad CRxMgrList,\"int get_free_slot() const;\""
		script = "Type.ad CRxMgrList,\"int calc_stuff_count() const;\""
		
	condition:
		true
}

//0434 CRxStuff* list[0x6c];
rule CRxMgrList_list
{
	meta:
		script = "$result = [@pattern + 0x2f]"
		script = "Type.am CRxMgrList,CRxStuff*,list,0x6c,$result"
		script = "Type.mcomment CRxMgrList,list,\"最大数量0x6c(.108)个\""
	strings:
		$pattern = { C7 81 [4] FF FF FF FF E9 [4] 80 BA [4] 00 [4] 01 [2] A1 [4] 83 BC B0 [4] 00 }
	condition:
		#pattern == 1
}


//0610 SlotState states[0x6c]
//162c uint32_t list_id;
//1c58 uint32_t list_arg;
rule CRxMgrList_states
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrList,SlotState,states,0x6c,$result"
		script = "$result = [@pattern + 0x2b]"
		script = "Type.am CRxMgrList,uint32_t,list_id,0,$result"
		script = "$result = [@pattern + 0x44]"
		script = "Type.am CRxMgrList,uint32_t,list_arg,0,$result"
	strings:
		$pattern = { 80 [5] 00 [9] 00 00 00 00 [8] 83 [5] 00 [6] 8B [7] 0D [4] 45 [2] 8B [2] 8B [5] 8B }
	condition:
		#pattern == 1
}

//1a14 CRxWnd * dlg_input
rule CRxMgrList_dlg_input
{
	meta:
		script = "$result = [@pattern + 0x19]"
		script = "Type.am CRxMgrList,CRxWnd*,dlg_input,0,$result"
		script = "Type.mcomment CRxMgrList,dlg_input,\"各种仅需要输入数量的无价格标签窗口\""
	strings:
		$pattern = { 83 B8 [4] 00 [6] C7 80 [4] 01 00 00 00 8B 8E [4] C6 86 [4] 01 88 9E [4] E8 }
	condition:
		#pattern == 1
}

//1a38 CRxWnd * dlg_price;
rule CRxMgrList_dlg_price
{
	meta:
		script = "$result = [@pattern + 0xa]"
		script = "Type.am CRxMgrList,CRxWnd*,dlg_price,0,$result"
		script = "Type.mcomment CRxMgrList,dlg_price,\"物品买卖输入数量窗口，有价格标签同步显示价格\""
	strings:
		$pattern = { 83 CF FF 6A 78 89 7D ?? 89 86 [4] E8 [4] 8B 8E [4] 83 C4 08 6A 01 E8 }
	condition:
		#pattern == 1
}

//1a60 CRxWnd * dlg_myshop_price;
rule CRxMgrList_dlg_myshop_price
{
	meta:
		script = "$result = [@pattern + 0x26]"
		script = "Type.am CRxMgrList,CRxWnd*,dlg_myshop_price,0,$result"
		script = "Type.mcomment CRxMgrList,dlg_myshop_price,\"开店输入出售价格窗口\""
	strings:
		$pattern = { 6A 01 6A 01 ?? 68 [4] 68 2C 01 00 00 [3] E8 [4] EB [6] FF 6A 78 89 7D ?? 89 86 [4] E8 [4] 8B 8E [4] 83 C4 08 6A 00 }
	condition:
		#pattern == 1
}

//1a78 CRxWnd * dlg_sell_confirm;
rule CRxMgrList_dlg_sell_confirm
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrList,CRxWnd*,dlg_sell_confirm,0,$result"
		script = "Type.mcomment CRxMgrList,dlg_sell_confirm,\"卖店属性物品确认窗口\""
	strings:
		$pattern = { 8B 8E [4] 6A 01 E8 [4] 8B 0D [4] 68 5E 01 00 00 E8 [4] 8B 0D [4] 50 68 5D 01 00 00 E8 }
	condition:
		#pattern == 1
}

//1a8c CRxWnd * dlg_break_confirm;
rule CRxMgrList_dlg_break_confirm
{
	meta:
		script = "$result = [@pattern + 0x22]"
		script = "Type.am CRxMgrList,CRxWnd*,dlg_break_confirm,0,$result"
		script = "Type.mcomment CRxMgrList,dlg_break_confirm,\"分解属性物品确认窗口\""
	strings:
		$pattern = { 6A 01 6A 01 56 68 [4] 6A 5F 57 8B C8 E8 [4] EB ?? 33 C0 [2] FF [2] 89 7D ?? 89 86 }
	condition:
		#pattern == 1
}

//1ab0 uint32_t breaker_num;
rule CRxMgrList_breaker_num
{
	meta:
		script = "$result = [@pattern + 0x1e]"
		script = "Type.am CRxMgrList,uint32_t,breaker_num,0,$result"
		script = "Type.mcomment CRxMgrList,breaker_num,\"仅用于分解(背包列表)\""
	strings:
		$pattern = { 83 BB [4] 01 7E ?? 8B CB E8 [4] 8B 93 [4] 8B 8B [4] 89 BB [4] A1 }
	condition:
		#pattern == 1
}

//1ad0 CRxWnd * dlg_drop_confirm;
rule CRxMgrList_dlg_drop_confirm
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrList,CRxWnd*,dlg_drop_confirm,0,$result"
		script = "Type.mcomment CRxMgrList,dlg_drop_confirm,\"扔掉物品确认窗口(背包列表)\""
	strings:
		$pattern = { 8B 8E [4] 6A 01 E8 [4] 8B 0D [4] 68 5C 01 00 00 E8 [4] 8B 0D [4] 50 68 5D 01 00 00 E8 }
	condition:
		#pattern == 1
}

//1b10 CRxWnd * dlg_flyring_confirm;
rule CRxMgrList_dlg_flyring_confirm
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrList,CRxWnd*,dlg_flyring_confirm,0,$result"
		script = "Type.mcomment CRxMgrList,dlg_flyring_confirm,\"使用戒指传送确认窗口(背包列表)\""
	strings:
		$pattern = { 8B [5] 8B [5] ?? E8 [6] FF 8D [6] 42 00 00 00 }
	condition:
		#pattern == 1
}

//1c5c uint32_t max_size;
rule CRxMgrList_max_size
{
	meta:
		script = "$result = [@pattern + 0xf]"
		script = "Type.am CRxMgrList,uint32_t,max_size,0,$result"
		script = "Type.mcomment CRxMgrList,max_size,\"列表有效单元数量\""
	strings:
		$pattern = { 83 FE FF [7] FF [2] 8B 87 [4] 89 45 [10] 00 00 00 00 [3] 01 00 00 00 }
	condition:
		#pattern == 1
}

rule CRxMgrList_end
{
	meta:
		script = "Type.print SlotState,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "Type.print CRxMgrList,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}