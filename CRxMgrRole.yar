
//
//CRxMgrRole部分成员分析
//

rule CRxMgrRole_start
{
	meta:
		script = "Type.as CRxMgrRole"
		script = "Type.aanc CRxMgrRole,CRxMgr"
		script = "Type.ad CRxMgrRole,\"static const int enter_id = 0x7d1;\""
		script = "Type.ad CRxMgrRole,\"static const int back_id = 0x7d2;\""
		script = "Type.ad CRxMgrRole,\"static const int create_id = 0x7d3;\""
		script = "Type.ad CRxMgrRole,\"static const int delete_id = 0x7d4;\""
		
		script = "Type.ad CRxMgrRole,\"bool select_role(uint32_t nRoleIndex);\""
		script = "Type.ad CRxMgrRole,\"bool select_role(const char * roleName);\""
		script = "Type.ad CRxMgrRole,\"bool select_role_uid(uint32_t uid);\""
		script = "Type.ad CRxMgrRole,\"int find_role_uid(const char * cpName);\""
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
		$pattern = { 6A 01 6A 01 56 68 [4] 52 51 8B C8 E8 [4] EB ?? 33 C0 53 8B C8 88 5D ?? 89 86 [4] E8 [4] 8B 8E [4] 53 E8 [4] 8B 8E [4] 53 E8 [4] 8B 8E [4] E8 [4] D9 05 [4] 6A 04 [90] C7 85 [4] 2B 00 00 00 C7 85 [4] 75 00 00 00 C7 85 [4] 47 00 00 00 E8 [4] 6A 01 68 [4] 89 86 [4] E8 [4] 6A 01 }
	condition:
		#pattern == 1
}

//8e4 uint32_t roleCount;
//8e8 uint32_t roleMaxCount;
rule CRxMgrRole_roleCount
{
	meta:
		script = "$result = [@pattern + 0x08]"
		script = "Type.am CRxMgrRole,uint32_t,roleCount,0,$result"
		script = "Type.mcomment CRxMgrRole,roleCount,\"可选人物数量\""
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxMgrRole,uint32_t,roleMaxCount,0,$result"
		script = "Type.mcomment CRxMgrRole,roleMaxCount,\"最大可创建人物数量\""
	strings:
		$pattern = { 8B BE [4] 39 BE [4] 7C ?? 6A 7F 50 8D 8D [4] 51 88 85 [4] E8 [4] 8B 0D [4] 83 C4 0C 57 68 33 11 00 00 E8}
	condition:
		#pattern == 1	
}

//8ec uint32_t roleUIDList[8];
rule CRxMgrRole_roleUIDList
{
	meta:
		script = "$result = [@pattern + 0x2c]"
		script = "Type.am CRxMgrRole,uint32_t,roleUIDList,8,$result"
		script = "Type.mcomment CRxMgrRole,roleUIDList,\"人物索引，-1表示没有人物\""
			
	strings:
		$pattern = { 8D BE [4] BB 06 00 00 00 8B 0F 6A 00 68 [4] E8 [4] 83 C7 04 4B 75 ?? 8B 8E [4] E8 [4] 8D BE [4] BB 08 00 00 00 8B FF 81 3F FF FF 00 00}
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
