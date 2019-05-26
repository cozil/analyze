rule CRxLbItem_start
{
	meta:
		script = "Type.as CRxLbItem"
		script = "Type.aanc CRxLbItem,CRxCtrl"
		script = "Type.comment CRxLbItem,\"CListBox类的列表项结构 Type=0x25\""
		script = "Type.as RX_LB_COLUMN"
		script = "Type.am RX_LB_COLUMN,char,value,0x80"
	condition:
		true
}

//uint32_t itemdata;
rule CRxLbItem_itemdata
{
	meta:
		script = "$result = [@pattern + 0x8]"
		script = "Type.am CRxLbItem,uint32_t,itemdata,0,$result"
	strings:
		$pattern = { 8B 8B [4] 8B 93 [6] 8B 40 ?? 6A 00 ?? 68 F4 03 00 00 FF D0 80 BB [4] 00 }
	condition:
		#pattern == 1
}

//uint32_t colcount;
rule CRxLbItem_colcount
{
	meta:
		script = "$result = [@pattern + 0x13]"
		script = "Type.am CRxLbItem,uint32_t,colcount,0,$result"
	strings:
		$pattern = { 8B 45 ?? 83 6D ?? 80 03 77 ?? 83 C7 04 40 89 45 ?? 3B 83 }
	condition:
		#pattern == 1
}

//char texts[8][0x80];
rule CRxLbItem_texts
{
	meta:
		script = "$result = [@pattern + 0x9]"
		script = "Type.am CRxLbItem,RX_LB_COLUMN,texts,8,$result+0x80"
	strings:
		$pattern = { 6A 7F C1 E2 07 51 8D 84 3A [4] 50 E8 [4] 83 C4 0C C7 84 B7 [4] 00 00 00 00 }
	condition:
		#pattern == 1
}

rule CRxLbItem_end
{
	meta:
		script = "Type.print RX_LB_COLUMN,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "Type.print CRxLbItem,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}

rule CRxListBox_start
{
	meta:
		script = "Type.as CRxListBox"
		script = "Type.aanc CRxListBox,CRxCtrl"
		script = "Type.comment CRxListBox,\"CListBox控件结构 Type=0x24\""
		script = "Type.ad CRxListBox,\"int calc_item_count(int columnid/*1-based*/) const;\""
		script = "Type.ad CRxListBox,\"int read_items(StringArray& strList, int columnid) const;\""
		script = "Type.ad CRxListBox,\"bool select_item(const char * cpName, int columnid);\""
		script = "Type.ad CRxListBox,\"bool select_item(int nItemIndex);\""
		script = "Type.ad CRxListBox,\"int find_item(const char *cpName, int columnid) const;\""
	condition:
		true
}

//22c CRxLbItem * items[0x32];
rule CRxListBox_items
{
	meta:
		script = "$result = [@pattern + 0x3]"
		script = "Type.am CRxListBox,CRxLbItem*,items,0x32,$result"
	strings:
		$pattern = { 8D 9C 8E [4] EB [8] 8B 45 ?? 8B 4D ?? 8B 96 [8] 0F 8F }
	condition:
		#pattern == 1
}

rule CRxListBox_end
{
	meta:
		script = "Type.print CRxListBox,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
