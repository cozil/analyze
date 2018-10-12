rule CRxMgrList_start
{
	meta:
		script = "Type.as CRxMgrList"
		script = "Type.aanc CRxMgrList,CRxMgr"
		script = "Type.as SlotState"
		script = "Type.am SlotState,char,enabled"
		script = "Type.am SlotState,char,pad_01,0x23"

		script = "Type.ad CRxMgrList,\"inline void click_price_confirm() {{ click(0x60);}} //NPC商店购买物品输入数量确认/取消\""
		script = "Type.ad CRxMgrList,\"inline void click_price_cancel() {{ click(0x61);}}\""	
		
		script = "Type.ad CRxMgrList,\"inline void click_input_confirm() {{ click(0x62);}} //仓库取物品输入数量确认/取消\""
		script = "Type.ad CRxMgrList,\"inline void click_input_cancel() {{ click(0x63);}}\""		
	
		script = "Type.ad CRxMgrList,\"inline void click_myshop_confirm() {{ click(0x5a);}} //开店输入数量确认/取消\""
		script = "Type.ad CRxMgrList,\"inline void click_myshop_cancel() {{ click(0x5b);}}\""	
		
		script = "Type.ad CRxMgrList,\"inline void click_drop_confirm() {{ click(0x5c);}} //扔掉属性物品确认/取消\""
		script = "Type.ad CRxMgrList,\"inline void click_drop_cancel() {{ click(0x5d);}}\""	
			
		script = "Type.ad CRxMgrList,\"inline void click_sell_confirm() {{ click(0x5e);}} //属性物品卖店确认/取消\""
		script = "Type.ad CRxMgrList,\"inline void click_sell_cancel() {{ click(0x5f);}}\""
		
		script = "Type.ad CRxMgrList,\"inline void click_flyring_confirm() {{ click(0xc9);}} //戒指传送确认/取消\""
		script = "Type.ad CRxMgrList,\"inline void click_flyring_cancel() {{ click(0xca);}}\""	
		
		script = "Type.ad CRxMgrList,\"inline void click_break_confirm() {{ click(0xcb);}} //属性物品分解确认/取消\""
		script = "Type.ad CRxMgrList,\"inline void click_break_cancel() {{ click(0xcc);}}\""
		
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
		$pattern = { 80 BB [4] 00 [9] 00 00 00 00 [8] 83 BA [4] 00 0F 84 [4] 8B BF [6] 0D [4] 45 [2] 8B 75 ?? 8B 82 [4] 8B B6 }
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
		script = "$result = [@pattern + 0x34]"
		script = "Type.am CRxMgrList,CRxWnd*,dlg_flyring_confirm,0,$result"
		script = "Type.mcomment CRxMgrList,dlg_drop_confirm,\"使用戒指传送确认窗口(背包列表)\""
	strings:
		$pattern = { 6A 01 [2] 6A 73 68 03 01 00 00 6A 05 6A 3C 6A 14 [2] E8 [9] 68 [6] 89 7D ?? 89 86 [4] E8 [4] 8B 8E }
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