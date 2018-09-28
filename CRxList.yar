rule CRxList_start
{
	meta:
		script = "Type.as CRxList"
		script = "Type.aanc CRxList,CRxObject"
		script = "Type.as SlotState"
		script = "Type.am SlotState,char,enabled"
		script = "Type.am SlotState,char,pad_01,0x23"
	condition:
		true
}

rule CRxList_list
{
	meta:
		script = "$result = [@pattern + 0x2f]"
		script = "Type.am CRxList,CRxStuff*,list,0x6c,$result"
		script = "Type.mcomment CRxList,list,\"最大数量0x6c(.108)个\""
	strings:
		$pattern = { C7 81 [4] FF FF FF FF E9 [4] 80 BA [4] 00 [4] 01 [2] A1 [4] 83 BC B0 [4] 00 }
	condition:
		#pattern == 1
}


//SlotState states[0x6c]
//int list_id;
//int list_arg;
rule CRxList_states
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxList,SlotState,states,0x6c,$result"
		script = "$result = [@pattern + 0x2b]"
		script = "Type.am CRxList,int,list_id,0,$result"
		script = "$result = [@pattern + 0x44]"
		script = "Type.am CRxList,int,list_arg,0,$result"
	strings:
		$pattern = { 80 BB [4] 00 [9] 00 00 00 00 [8] 83 BA [4] 00 0F 84 [4] 8B BF [6] 0D [4] 45 [2] 8B 75 ?? 8B 82 [4] 8B B6 }
	condition:
		#pattern == 1
}

//CRxWnd * dlg_input
rule CRxList_dlg_input
{
	meta:
		script = "$result = [@pattern + 0x19]"
		script = "Type.am CRxList,CRxWnd*,dlg_input,0,$result"
		script = "Type.mcomment CRxList,dlg_input,\"各种仅需要输入数量的无价格标签窗口\""
	strings:
		$pattern = { 83 B8 [4] 00 [6] C7 80 [4] 01 00 00 00 8B 8E [4] C6 86 [4] 01 88 9E [4] E8 }
	condition:
		#pattern == 1
}

//CRxButton * input_bn_confirm;
//CRxButton * input_bn_cancel;
rule CRxList_input_bn
{
	meta:
		script = "$result = [@pattern + 0x17]"
		script = "Type.am CRxList,CRxButton*,input_bn_confirm,0,$result"
		script = "$result = [@pattern + 0x2c]"
		script = "Type.am CRxList,CRxButton*,input_bn_cancel,0,$result"
	strings:
		$pattern = { 6A 00 [3] 6A 00 6A 63 68 [4] 68 [4] 6A 00 89 86 [11] E8 [4] 83 C4 50 89 86 }
	condition:
		#pattern == 1
}

//CRxWnd * dlg_price;
rule CRxList_dlg_price
{
	meta:
		script = "$result = [@pattern + 0xa]"
		script = "Type.am CRxList,CRxWnd*,dlg_price,0,$result"
		script = "Type.mcomment CRxList,dlg_price,\"物品买卖输入数量窗口，有价格标签同步显示价格\""
	strings:
		$pattern = { 83 CF FF 6A 78 89 7D ?? 89 86 [4] E8 [4] 8B 8E [4] 83 C4 08 6A 01 E8 }
	condition:
		#pattern == 1
}

//CRxButton * price_bn_confirm;
//CRxButton * price_bn_cancel;
rule CRxList_price_bn
{
	meta:
		script = "$result = [@pattern + 0x1b]"
		script = "Type.am CRxList,CRxButton*,price_bn_confirm,0,$result"
		script = "$result = [@pattern + 0x2f]"
		script = "Type.am CRxList,CRxButton*,price_bn_cancel,0,$result"
	strings:
		$pattern = { 6A 00 6A 00 D9 5D ?? 8B 55 ?? 6A 61 68 [4] 68 [4] 6A 00 52 89 86 [4] 8B 45 [4] E8 [7] 89 86 }
	condition:
		#pattern == 1
}

//CRxWnd * dlg_myshop_price;
rule CRxList_dlg_myshop_price
{
	meta:
		script = "$result = [@pattern + 0x26]"
		script = "Type.am CRxList,CRxWnd*,dlg_myshop_price,0,$result"
		script = "Type.mcomment CRxList,dlg_myshop_price,\"开店输入出售价格窗口\""
	strings:
		$pattern = { 6A 01 6A 01 ?? 68 [4] 68 2C 01 00 00 [3] E8 [4] EB [6] FF 6A 78 89 7D ?? 89 86 [4] E8 [4] 8B 8E [4] 83 C4 08 6A 00 }
	condition:
		#pattern == 1
}

//CRxButton * myshop_bn_confirm;
rule CRxList_myshop_bn_confirm
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxList,CRxButton*,myshop_bn_confirm,0,$result"
	strings:
		$pattern = { 6A 5A [3] B2 00 00 00 [3] 55 ?? 68 B2 00 00 00 6A 55 [2] E8 [9] 6A 78 [3] 89 86 }
	condition:
		#pattern == 1
}

//CRxButton * myshop_bn_cancel;
rule CRxList_myshop_bn_cancel
{
	meta:
		script = "$result = [@pattern + 0x2e]"
		script = "Type.am CRxList,CRxButton*,myshop_bn_cancel,0,$result"
	strings:
		$pattern = { 6A 5B [3] B2 00 00 00 [3] 9C 00 00 00 ?? 68 B2 00 00 00 68 9C 00 00 00 [2] E8 [9] 6A 78 89 7D ?? 89 86 }
	condition:
		#pattern == 1
}

//CRxWnd * dlg_sell_confirm;
rule CRxList_dlg_sell_confirm
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxList,CRxWnd*,dlg_sell_confirm,0,$result"
		script = "Type.mcomment CRxList,dlg_sell_confirm,\"卖店属性物品确认窗口\""
	strings:
		$pattern = { 8B 8E [4] 6A 01 E8 [4] 8B 0D [4] 68 5E 01 00 00 E8 [4] 8B 0D [4] 50 68 5D 01 00 00 E8 }
	condition:
		#pattern == 1
}

//CRxLabelEx * sell_lb_text;
rule CRxList_sell_lb_text
{
	meta:
		script = "$result = [@pattern + 0x7b]"
		script = "Type.am CRxList,CRxLabelEx*,sell_lb_text,0,$result"
	strings:
		$pattern = { 68 5E 01 00 00 [75] 6A 01 [2] 6A 73 68 03 01 00 00 6A 05 6A 3C 6A 14 [2] E8 [9] 8D 95 [7] 89 7D ?? 89 86 }
	condition:
		#pattern == 1
}


//CRxButton * sell_bn_confirm;
rule CRxList_sell_bn_confirm
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxList,CRxButton*,sell_bn_confirm,0,$result"
	strings:
		$pattern = { 6A 5E [3] B2 00 00 00 [3] 55 ?? 68 B2 00 00 00 6A 55 [2] E8 [9] 6A 78 89 7D ?? 89 86 }
	condition:
		#pattern == 1
}

//CRxButton * sell_bn_close;
rule CRxList_sell_bn_close
{
	meta:
		script = "$result = [@pattern + 0x2e]"
		script = "Type.am CRxList,CRxButton*,sell_bn_close,0,$result"
	strings:
		$pattern = { 6A 5F [3] B2 00 00 00 [3] 9C 00 00 00 ?? 68 B2 00 00 00 68 9C 00 00 00 [2] E8 [9] 6A 78 89 7D ?? 89 86 }
	condition:
		#pattern == 1
}

//CRxWnd * dlg_break_confirm;
rule CRxList_dlg_break_confirm
{
	meta:
		script = "$result = [@pattern + 0x22]"
		script = "Type.am CRxList,CRxWnd*,dlg_break_confirm,0,$result"
		script = "Type.mcomment CRxList,dlg_break_confirm,\"分解属性物品确认窗口\""
	strings:
		$pattern = { 6A 01 6A 01 56 68 [4] 6A 5F 57 8B C8 E8 [4] EB ?? 33 C0 [2] FF [2] 89 7D ?? 89 86 }
	condition:
		#pattern == 1
}

//CRxLabelEx * break_lb_text;
rule CRxList_break_lb_text
{
	meta:
		script = "$result = [@pattern + 0x4d]"
		script = "Type.am CRxList,CRxLabelEx*,break_lb_text,0,$result"
	strings:
		$pattern = { 68 80 00 00 00 [36] 6A 01 [2] 6A 73 68 03 01 00 00 6A 05 6A 3C 6A 14 [2] E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//CRxButton * break_bn_confirm;
rule CRxList_break_bn_confirm
{
	meta:
		script = "$result = [@pattern + 0x2b]"
		script = "Type.am CRxList,CRxButton*,break_bn_confirm,0,$result"
	strings:
		$pattern = { 68 CB 00 00 00 [3] B2 00 00 00 [3] 55 ?? 68 B2 00 00 00 6A 55 [2] E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//CRxButton * break_bn_close;
rule CRxList_break_bn_close
{
	meta:
		script = "$result = [@pattern + 0x31]"
		script = "Type.am CRxList,CRxButton*,break_bn_close,0,$result"
	strings:
		$pattern = { 68 CC 00 00 00 [3] B2 00 00 00 [3] 9C 00 00 00 ?? 68 B2 00 00 00 68 9C 00 00 00 [2] E8 [4] EB ?? 33 C0 8B 96 [4] 89 86 }
	condition:
		#pattern == 1
}

//int breaker_num;
rule CRxList_breaker_num
{
	meta:
		script = "$result = [@pattern + 0x1e]"
		script = "Type.am CRxList,int,breaker_num,0,$result"
		script = "Type.mcomment CRxList,breaker_num,\"仅用于分解(背包列表)\""
	strings:
		$pattern = { 83 BB [4] 01 7E ?? 8B CB E8 [4] 8B 93 [4] 8B 8B [4] 89 BB [4] A1 }
	condition:
		#pattern == 1
}

//CRxWnd * dlg_drop_confirm;
rule CRxList_dlg_drop_confirm
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxList,CRxWnd*,dlg_drop_confirm,0,$result"
		script = "Type.mcomment CRxList,dlg_drop_confirm,\"扔掉物品确认窗口(背包列表)\""
	strings:
		$pattern = { 8B 8E [4] 6A 01 E8 [4] 8B 0D [4] 68 5C 01 00 00 E8 [4] 8B 0D [4] 50 68 5D 01 00 00 E8 }
	condition:
		#pattern == 1
}


//CRxLabelEx * drop_lb_text;
rule CRxList_drop_lb_text
{
	meta:
		script = "$result = [@pattern + 0x7b]"
		script = "Type.am CRxList,CRxLabelEx*,drop_lb_text,0,$result"
	strings:
		$pattern = { 68 5C 01 00 00 [75] 6A 01 [2] 6A 73 68 03 01 00 00 6A 05 6A 3C 6A 14 [2] E8 [9] 8D 95 [10] 89 86 }
	condition:
		#pattern == 1
}


//CRxButton * drop_bn_confirm;
rule CRxList_drop_bn_confirm
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxList,CRxButton*,drop_bn_confirm,0,$result"
	strings:
		$pattern = { 6A 5C [3] B2 00 00 00 [3] 55 ?? 68 B2 00 00 00 6A 55 [2] E8 [9] 6A 78 89 7D ?? 89 86 }
	condition:
		#pattern == 1
}


//CRxButton * drop_bn_close;
rule CRxList_drop_bn_close
{
	meta:
		script = "$result = [@pattern + 0x2e]"
		script = "Type.am CRxList,CRxButton*,drop_bn_close,0,$result"
	strings:
		$pattern = { 6A 5D [3] B2 00 00 00 [3] 9C 00 00 00 ?? 68 B2 00 00 00 68 9C 00 00 00 [2] E8 [9] 6A 78 89 7D ?? 89 86 }
	condition:
		#pattern == 1
}



//CRxWnd * dlg_flyring_confirm;
//CRxLabelEx * flyring_lb_text;
rule CRxList_dlg_flyring_confirm
{
	meta:
		script = "$result = [@pattern + 0x34]"
		script = "Type.am CRxList,CRxWnd*,dlg_flyring_confirm,0,$result"
		script = "Type.mcomment CRxList,dlg_drop_confirm,\"使用戒指传送确认窗口(背包列表)\""
		script = "$result = [@pattern + 0x29]"
		script = "Type.am CRxList,CRxLabelEx*,flyring_lb_text,0,$result"
	strings:
		$pattern = { 6A 01 [2] 6A 73 68 03 01 00 00 6A 05 6A 3C 6A 14 [2] E8 [9] 68 [6] 89 7D ?? 89 86 [4] E8 [4] 8B 8E }
	condition:
		#pattern == 1
}

//CRxButton * flyring_bn_confirm;
rule CRxList_flyring_bn_confirm
{
	meta:
		script = "$result = [@pattern + 0x2b]"
		script = "Type.am CRxList,CRxButton*,flyring_bn_confirm,0,$result"
	strings:
		$pattern = { 68 C9 00 00 00 [3] B2 00 00 00 [3] 55 ?? 68 B2 00 00 00 6A 55 [2] E8 [9] 6A 78 89 7D ?? 89 86 }
	condition:
		#pattern == 1
}

//CRxButton * flyring_bn_close;
rule CRxList_flyring_bn_close
{
	meta:
		script = "$result = [@pattern + 0x31]"
		script = "Type.am CRxList,CRxButton*,flyring_bn_close,0,$result"
	strings:
		$pattern = { 68 CA 00 00 00 [3] B2 00 00 00 [3] 9C 00 00 00 ?? 68 B2 00 00 00 68 9C 00 00 00 [2] E8 [9] 6A 78 89 7D ?? 89 86 }
	condition:
		#pattern == 1
}

rule CRxList_max_size
{
	meta:
		script = "$result = [@pattern + 0xf]"
		script = "Type.am CRxList,int,max_size,0,$result"
		script = "Type.mcomment CRxList,max_size,\"列表有效单元数量\""
	strings:
		$pattern = { 83 FE FF [7] FF [2] 8B 87 [4] 89 45 [10] 00 00 00 00 [3] 01 00 00 00 }
	condition:
		#pattern == 1
}

rule CRxList_end
{
	meta:
		script = "Type.print CRxList,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}