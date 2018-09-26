
//
//CRxMgrRole部分成员分析
//

rule CRxMgrRole_start
{
	meta:
		script = "Type.as CRxMgrRole"
		script = "Type.aanc CRxMgrRole,CRxMgr"
	condition:
		true
}

//8d4 CRxWnd * dlg_rolelist;
//8d8 CRxListBox * lbx_roleList;
rule CRxMgrRole_dlg_rolelist
{
	meta:
		script = "$result = [@pattern + 0x1f]"
		script = "Type.am CRxMgrRole,CRxWnd*,dlg_rolelist,0,$result"
		script = "$result = [@pattern + 0xd9]"
		script = "Type.am CRxMgrRole,CRxListBox*,lbx_roleList,0,$result"
	strings:
		$pattern = { 6A 01 6A 01 56 68 [4] 52 51 8B C8 E8 [4] EB ?? 33 C0 53 8B C8 88 5D ?? 89 86 [4] E8 [4] 8B 8E [4] 53 E8 [4] 8B 8E [4] 53 E8 [4] 8B 8E [4] E8 [4] D9 05 [4] 6A 04 [90] C7 85 [4] 2B 00 00 00 C7 85 [4] 75 00 00 00 C7 85 [4] 47 00 00 00 E8 [4] 6A 01 68 [4] 89 86 [4] E8 [4] 6A 01}
	condition:
		#pattern == 1	
}

//8e4 int roleCount;
//8e8 int roleMaxCount;
rule CRxMgrRole_roleCount
{
	meta:
		script = "$result = [@pattern + 0x08]"
		script = "Type.am CRxMgrRole,int,roleCount,0,$result"
		script = "Type.mcomment CRxMgrRole,roleCount,\"可选人物数量\""
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxMgrRole,int,roleMaxCount,0,$result"
		script = "Type.mcomment CRxMgrRole,roleMaxCount,\"最大可创建人物数量\""
	strings:
		$pattern = { 8B BE [4] 39 BE [4] 7C ?? 6A 7F 50 8D 8D [4] 51 88 85 [4] E8 [4] 8B 0D [4] 83 C4 0C 57 68 33 11 00 00 E8}
	condition:
		#pattern == 1	
}

//8ec int roleUIDList[8];
rule CRxMgrRole_roleUIDList
{
	meta:
		script = "$result = [@pattern + 0x2c]"
		script = "Type.am CRxMgrRole,int,roleUIDList,8,$result"
		script = "Type.mcomment CRxMgrRole,roleUIDList,\"人物索引，-1表示没有人物\""
			
	strings:
		$pattern = { 8D BE [4] BB 06 00 00 00 8B 0F 6A 00 68 [4] E8 [4] 83 C7 04 4B 75 ?? 8B 8E [4] E8 [4] 8D BE [4] BB 08 00 00 00 8B FF 81 3F FF FF 00 00}
	condition:
		#pattern == 1	
}



//1224 CRxButton * bn_enter;
rule CRxMgrRole_bn_enter
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxMgrRole,CRxButton*,bn_enter,0,$result"
	strings:
		$pattern = { 8B 8D [4] 8B 95 [4] 68 [4] 68 D1 07 00 00 56 51 52 53 53 8B C8 E8 [4] EB ?? 33 C0 89 86 [4] 8D 4E ?? 89 48}
	condition:
		#pattern == 1	
}

//1228 CRxButton * bn_back;
rule CRxMgrRole_bn_back
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "Type.am CRxMgrRole,CRxButton*,bn_back,0,$result"
	strings:
		$pattern = { 8B 8D [4] 8B 95 [4] 68 [4] 68 D2 07 00 00 56 81 C1 6B 01 00 00 51 83 C2 15 52 68 6B 01 00 00 6A 15 8B C8 E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 [4] 83 C1 28 89 48}
	condition:
		#pattern == 1	
}

//122c CRxButton * bn_delete;
rule CRxMgrRole_bn_delete
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "Type.am CRxMgrRole,CRxButton*,bn_delete,0,$result"
	strings:
		$pattern = { 8B 8D [4] 8B 95 [4] 68 [4] 68 D4 07 00 00 56 81 C1 37 01 00 00 51 83 C2 15 52 68 37 01 00 00 6A 15 8B C8 E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 [4] 83 C1 28 89 48}
	condition:
		#pattern == 1	
}

//122c CRxButton * bn_create;
rule CRxMgrRole_bn_create
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "Type.am CRxMgrRole,CRxButton*,bn_create,0,$result"
	strings:
		$pattern = { 8B 8D [4] 8B 95 [4] 68 [4] 68 D3 07 00 00 56 81 C1 03 01 00 00 51 83 C2 15 52 68 03 01 00 00 6A 15 8B C8 E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 [4] 83 C1 28 89 48}
	condition:
		#pattern == 1	
}



rule CRxMgrRole_end
{
	meta:
		script = "Type.print CRxMgrRole,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
