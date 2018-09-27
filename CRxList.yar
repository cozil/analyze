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
		script = "Type.am CRxList,CRxStuff,list,0x6c,$result"
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
		$pattern = { 80 BB [4] 00 [9] 00 [8] 83 BA [4] 00 0F 84 [4] 8B BF [6] 0D [4] 45 [2] 8B 75 ?? 8B 82 [4] 8B B6 }
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
		script = "Type.am CRxList,CRxWnd,dlg_myshop_price,0,$result"
		script = "Type.mcomment CRxList,dlg_myshop_price,\"开店输入出售价格窗口\""
	strings:
		$pattern = { 6A 01 6A 01 ?? 68 [4] 68 2C 01 00 00 [3] E8 [4] EB [6] FF 6A 78 89 7D ?? 89 86 [4] E8 [4] 8B 8E [4] 83 C4 08 6A 00 }
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