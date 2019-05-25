
//
//CRxApp中的部分成员偏移分析
//

rule CRxApp_start
{
	meta:
		script = "Type.as CRxApp"
		script = "$offset = 0x10"
		script = "Type.ad CRxApp,\"inline bool is_valid_tlf_id(uint32_t id) const {{ return (id < _countof(save_name) && save_name[id].val[0]); }}\""
		script = "Type.ad CRxApp,\"inline bool is_rxf_exist() const {{ return (rxf_type == 2); }}\""
		script = "Type.ad CRxApp,\"inline bool has_charm() const {{ return (zzf_type != 0 || rxf_type != 0); }}\""
		script = "Type.ad CRxApp,\"bool is_dlg_blood(short gid) const;\""
		script = "Type.ad CRxApp,\"bool is_dlg_map(short gid) const;\""
	condition:
		true
}

//234 uint16_t zzf_type
//236 uint16_t rxf_type
rule CRxApp_zzf_type
{
	meta:
		script = "$result = [@pattern + 0x1b]"
		script = "Type.am CRxApp,uint16_t,zzf_type,0,$result"
		script = "Type.mcomment CRxApp,zzf_type,\"0 -- 无符　1 -- 玄武符 2 -- 银符 3 -- 金符\""
		script = "$result = [@pattern + 0x12]"
		script = "Type.am CRxApp,uint16_t,rxf_type,0,$result"
		script = "Type.mcomment CRxApp,rxf_type,\"至尊热血符，修改为2可以使用“/土灵符”指令作弊\""
	strings:
		//17014之前版本
		//$pattern = { 83 FF 58 0F 85 [4] 8B 0D [4] 66 39 99 [4] 7F ?? 66 39 99 [4] 75 ?? 38 1D [4] 75 ?? 68 A0 09 00 00 6A 09 }
		$pattern = { 83 FF 58 0F 85 [4] 8B 0D [4] 66 39 99 [4] 7F ?? 66 39 99 [4] 75 ?? 68 A0 09 00 00 6A 09 E8 }
	condition:
		#pattern == 1	
}

//CRxMgrTool * mgr_tool
rule CRxApp_mgr_tool
{
	meta:
		script = "$result = [@pattern +0x16]"
		script = "Type.am CRxApp,CRxMgrTool*,mgr_tool,0,$result"
		script = "Type.mcomment CRxApp,mgr_tool,\"快捷工具栏管理\""
	strings:
		//$pattern = { 68 [7] 01 89 83 [4] E8 [7] 89 85 [4] C6 45 ?? 09 } offset:0b
		$pattern = { 68 00 00 c8 ff eb ?? 6a ff E8 [4] 8B [5] 8B }
		
	condition:
		#pattern == 1
}

//288 CRxMgrState * mgr_state
rule CRxApp_mgr_state
{
	meta:	
		script = "$result = [@pattern + 0x6]"
		script = "Type.am CRxApp,CRxMgrState*,mgr_state,0,$result"
		script = "Type.mcomment CRxApp,mgr_state,\"状态窗口管理\""
	strings:
		$pattern = { c6 [2] 01 89 [5] 89 [5] e8 [16] 0a }
		
	condition:
		#pattern == 1
}

//CRxMgrEquip * mgr_equip
rule CRxApp_mgr_equip
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxApp,CRxMgrEquip*,mgr_equip,0,$result"
		script = "Type.mcomment CRxApp,mgr_equip,\"装备栏管理\""
	strings:
		$pattern = { 8B [5] 8B [5] E8 [8] 83 [5] 7B [6] 83 [5] 03 }		
	condition:
		#pattern == 1
}

//CRxMgrConfig * mgr_config;
rule CRxApp_mgr_config
{
	meta:
		script = "$result = [@pattern + 0x2e]"
		script = "Type.am CRxApp,CRxMgrConfig*,mgr_config,0,$result"
		script = "Type.mcomment CRxApp,mgr_config,\"游戏设定窗口管理器\""
	strings:
		$pattern = { C7 [5] 90 00 18 00 C7 [5] 01 00 00 00 [6] E8 [4] C6 [5] 01 89 [5] 8B }
		
	condition:
		#pattern == 1	
}

//CRxMgrMap * mgr_map;
rule CRxApp_mgr_map
{
	meta:
		script = "$result = [@pattern + 0x34]"
		script = "Type.am CRxApp,CRxMgrMap*,mgr_map,0,$result"
		script = "Type.mcomment CRxApp,mgr_map,\"游戏小地图管理对象\""
	strings:
		$pattern = { 81 [5] 48 3F 00 00 [3] C6 [5] 01 [30] 39 }		
	condition:
		#pattern == 1	
}

//CRxMgrExit * mgr_exit
rule CRxApp_mgr_exit
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxApp,CRxMgrExit*,mgr_exit,0,$result"
		script = "Type.mcomment CRxApp,mgr_exit,\"游戏退出管理\""
	strings:
		$pattern = { 8b [12] 6A 01 68 31 04 00 00 E8 [13] 00 }
	condition:
		#pattern == 1	
}

//CRxMgrTask * mgr_task;
rule CRxApp_mgr_task
{
	meta:
		script = "$result = [@pattern + 0x8]"
		script = "Type.am CRxApp,CRxMgrTask*,mgr_task,0,$result"
		script = "Type.mcomment CRxApp,mgr_task,\"任务管理对象\""
	strings:
		$pattern = { 8B [5] 8B [5] 8B [8] 06 [13] 6A 00 68 EA 03 00 00 68 F4 03 00 00 }
		
	condition:
		#pattern == 1	
}

//CRxMgrNpc * mgr_npc
rule CRxApp_mgr_npc
{
	meta:
		script = "$result = [@pattern +0x2b]"
		script = "Type.am CRxApp,CRxMgrNpc*,mgr_npc,0,$result"
		script = "Type.mcomment CRxApp,mgr_npc,\"NPC管理\""
	strings:
		$pattern = { 68 A1 03 00 00 6A 09 E8 [4] 33 C0 5F 5D C2 10 00 8B 81 [4] 8B 90 [4] 83 7A 40 00 0F 85 [4] 8B 81 [4] 8B 90 [4] 8B 92 }
	condition:
		#pattern == 1		
}

//CRxMgrMaker * mgr_maker;
rule CRxApp_mgr_maker
{
	meta:
		script = "$result = [@pattern + 0x19]"
		script = "Type.am CRxApp,CRxMgrMaker*,mgr_maker,0,$result"
		script = "Type.mcomment CRxApp,mgr_maker,\"制造管理\""
	strings:
		$pattern = { 68 1B 0B 00 00 6A 09 E8 [9] 8B [5] 8B }
	condition:
		#pattern == 1	
}

//CRxMgrSweet * mgr_sweet;
rule CRxApp_mgr_sweet
{
	meta:
		script = "$result = [@pattern + 0x21]"
		script = "Type.am CRxApp,CRxMgrSweet*,mgr_sweet,0,$result"
		script = "Type.mcomment CRxApp,mgr_sweet,\"情侣管理\""
	strings:
		$pattern = { 83 ?? 02 [4] 03 [4] 04 [4] 05 [4] 06 [8] 8B }
	condition:
		#pattern == 1
}


// CRxMgrDrug * mgr_drug; 
rule CRxApp_mgr_drug
{
	meta:
		script = "$result = [@pattern + 0x2a]"
		script = "Type.am CRxApp,CRxMgrDrug*,mgr_drug,0,$result"
		script = "Type.mcomment CRxApp,mgr_drug,\"制药管理对象\""
	strings:
		$pattern = { 83 ?? 01 [4] 02 [4] 03 [4] 04 [4] 05 [4] 06 [16] 8B [5] E8 }
		
	condition:
		#pattern == 1
}


//CRxMgrStrong * mgr_strong_c;
rule CRxApp_mgr_strong_c
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxApp,CRxMgrStrong*,mgr_strong_c,0,$result"
		script = "Type.mcomment CRxApp,mgr_strong_c,\"水晶符强化管理\""
	strings:
		$pattern = { 8B [28] 80 [5] 00 [9] 01 [18] 81 [5] B1 04 00 00  }
	condition:
		#pattern == 1
}

//CRxMgrDead * mgr_dead;
rule CRxApp_mgr_dead
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxApp,CRxMgrDead*,mgr_dead,0,$result"
		script = "Type.mcomment CRxApp,mgr_dead,\"死亡管理对象\""
	strings:
		$pattern = { 8B [5] 6A 03 ?? E8 [9] 8B [5] 6A 02 ?? E8 }
	condition:
		#pattern == 1
}

//CRxMgrPet * mgr_pet;
rule CRxApp_mgr_pet
{
	meta:
		script = "$result = [@pattern + 0xe]"
		script = "Type.am CRxApp,CRxMgrPet*,mgr_pet,0,$result"
		script = "Type.mcomment CRxApp,mgr_pet,\"宠物管理对象\""
	strings:
		$pattern = { 6A 00 E8 [9] 8B [5] 8B [5] 83 [2] 00 [2] 6A 01 6A 00 E8 }
	condition:
		#pattern == 1
}

//CRxMgrMaster * mgr_master;
rule CRxApp_mgr_master
{
	meta:
		script = "$result = [@pattern + 0xf]"
		script = "Type.am CRxApp,CRxMgrMaster*,mgr_master,0,$result"
		script = "Type.mcomment CRxApp,mgr_master,\"师徒管理对象\""
	strings:
		$pattern = { 3D D1 07 00 00 [2] 8B [5] 8B [5] E8 [10] D2 07 00 00 }
	condition:
		#pattern == 1
}


//394 CRxMgrTrade * mgr_trad
rule CRxApp_mgr_trad
{
	meta:
		script = "$result = [@pattern + 0x15]"
		script = "Type.am CRxApp,CRxMgrTrade*,mgr_trad,0,$result"
		script = "Type.mcomment CRxApp,mgr_trad,\"交易管理对象\""
	strings:
		$pattern = { 6A 31 6A 00 [2] E8 [6] 01 [5] 83 }
	condition:
		#pattern == 1		
}

//CRxMgrTeam * mgr_team;
rule CRxApp_mgr_team
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxApp,CRxMgrTeam*,mgr_team,0,$result"
		script = "Type.mcomment CRxApp,mgr_team,\"组队管理对象\""
	strings:
		$pattern = { 83 [5] 00 [6] 8B [8] 39 [5] 0F [5] 83 ?? 03 }
	condition:
		#pattern == 1		
}

//CRxMgrMyShop * mgr_myshop;
rule CRxApp_mgr_myshop
{
	meta:
		script = "$result = [@pattern + 0x13]"
		script = "Type.am CRxApp,CRxMgrMyShop*,mgr_myshop,0,$result"
		script = "Type.mcomment CRxApp,mgr_myshop,\"开店管理对象\""
	strings:
		$pattern = { 68 DC 04 00 00 6A 09 E8 [9] 8B [5] 85 ?? [12] 00 }
		
	condition:
		#pattern == 1		
}

//CRxMgrTlf * mgr_tlf;
rule CRxApp_mgr_tlf
{
	meta:
		script = "$result = [@pattern + 0x17]"
		script = "Type.am CRxApp,CRxMgrTlf*,mgr_tlf,0,$result"
		script = "Type.mcomment CRxApp,mgr_tlf,\"土灵符管理对象\""
	strings:
		$pattern = { 68 A1 03 00 00 6A 09 E8 [13] 8B }
	condition:
		#pattern == 1		
}

//CRxMgrCharm * mgr_charm;
rule CRxApp_mgr_charm
{
	meta:
		script = "$result = [@pattern + 0x2e]"
		script = "Type.am CRxApp,CRxMgrCharm*,mgr_charm,0,$result"
		script = "Type.mcomment CRxApp,mgr_charm,\"至尊、热血符管理\""
	strings:
		$pattern = { 81 ?? 7C DC 14 3C [12] E4 DC 14 3C [22] 8B }
		
	condition:
		#pattern == 1			
}

//CRxMgrMakerFrame * mgr_maker_frame;
rule CRxApp_mgr_maker_frame
{
	meta:
		script = "$result = [@pattern + 0xe]"
		script = "Type.am CRxApp,CRxMgrMakerFrame*,mgr_maker_frame,0,$result"
		script = "Type.mcomment CRxApp,mgr_maker_frame,\"制造分解窗口的框架窗口\""	
	strings:
		$pattern = { 6A 01 66 [2] [7] 8B [5] 6A 04 }
	condition:
		#pattern == 1	
}

//C0C int busy
rule CRxApp_busy
{
	meta:
		script = "$result = [@pattern + 0x07]"
		script = "Type.am CRxApp,int,busy,0,$result"
	strings:
		$pattern = { A1 [4] 83 B8 [4] 00 0F 85 [4] C7 80 [4] 01 00 00 00 8B 8E [4] C6 86 [4] 01 88 9E [4] E8 }
	condition:
		#pattern == 1			
}

//C23 char save_name[0x1e][0x0f]
rule CRxApp_save_name
{
	meta:
		script = "Type.as TlfName"
		script = "Type.am TlfName,char,val,0xf"
		script = "$result = [@pattern + 0x09]"
		script = "Type.am CRxApp,TlfName,save_name,0x1e,$result"
	strings:
		$pattern = { 8B 0D [11] 00 8B 0D [14] 68 53 05 00 00 E8 [4] ?? 68 80 00 00 00 ?? E8 [9] 68 57 04 00 00 E8 }
	condition:
		#pattern == 1			
}

rule CRxApp_end
{
	meta:
		script = "Type.print TlfName,0"
		script = "Type.print CRxApp,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
} 