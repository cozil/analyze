
//
//CRxApp中的部分成员偏移分析
//

rule CRxApp_start
{
	meta:
		script = "log \"struct CRxApp {\""
		script = "$offset = 0x10"
	condition:
		true
}

//CRxApp构造函数
rule CRxApp_create
{
	meta:
		script = "lblset @pattern, \"CRxApp::create\""
	strings:
		$pattern = { 55 8b ec 6a [10-100] e8 [4] 8d 8b [4] 89 7d ?? c7 03 [4] e8 [4] 68 34 2d 00 00 }
	condition:
		#pattern == 1
}


//234 short zzf_type
//236 short rxf_type
rule CRxApp_zzf_type
{
	meta:
		script = "$result = [@pattern + 0x1b]"
		script = "log \"/*{p:$offset}*/    char unused_{$offset}[0x{$result-$offset}];\""
		script = "log \"/*{p:$result}*/    short zzf_type;\""
		script = "$result = [@pattern + 0x12]"
		script = "log \"/*{p:$result}*/    short rxf_type;\""
		
	strings:
		$pattern = { 83 FF 58 0F 85 [4] 8B 0D [4] 66 39 99 [4] 7F ?? 66 39 99 [4] 75 ?? 38 1D [4] 75 ?? 68 A0 09 00 00 6A 09 }
	condition:
		#pattern == 1	
}

//280 CRxMgrTool * mgr_tool
//3a8 CRxMgrTeam * mgr_team
rule CRxApp_mgr_tool
{
	meta:
		script = "$result = [@pattern +0x55]"
		script = "log \"/*{p:$result}*/    CRxMgrTool * mgr_tool;\""
		
		//script = "$result = [@pattern +0x1f]"
		//script = "log \"/*{p:$result}*/    CRxMgrTeam * mgr_team;\""
				
	strings:
		$pattern = { 55 8B EC 8B 45 08 66 0F BE 48 06 [18] 83 B9 A8 03 00 00 00 [27] 83 F8 03 [17] 83 B8 80 02 00 00 00 }
	condition:
		#pattern == 1
}

//288 CRxMgrState * mgr_state
rule CRxApp_mgr_state
{
	meta:	
		script = "$offset = 0x09"
		script = "$pattern = @pattern1"
		script = "cmp #pattern1, 1"
		script = "je _RESULT"

		script = "$offset = 0x18"
		script = "$pattern = @pattern2"
		script = "cmp #pattern2, 1"
		script = "je _EXIT"

		script = "_RESULT:"
		script = "$result = [$pattern + $offset]"
		script = "log \"/*{p:$result}*/    CRxMgrState * mgr_state;\""
		script = "_EXIT:"
		script = "$offset = 0"
	strings:
		//对象引用位置
		$pattern1 = { 8B 25 [4] 51 8B 8A [4] E8 [4] F7 83 [4] 00 01 00 00 0F 84 [4] 66 83 BE [4] 03 0F 8C [4] 83 BE [4] 00 0F 85 [4] 8B 0D [4] 68 E1 09 00 00 6A 09 }
		//对象创建位置，所在函数为CRxApp构造函数
		$pattern2 = { 51 52 8B C8 E8 [4] EB ?? 33 C0 68 74 A6 03 00 C6 45 ?? 01 89 83 [4] 89 BB [4] E8 }
	condition:
		for any of them : (# == 1)
}

//28C CRxMgrEquip * mgr_equip
rule CRxApp_mgr_equip
{
	meta:
		script = "$result = [@pattern + 0x20]"
		script = "log \"/*{p:$result}*/    CRxMgrEquip * mgr_equip;\""
		//script = "$result = [@pattern + 0x26]"
		//script = "log \">>>>/*{p:$result}*/    CRxApp::mgr_equip::dlg\""
	strings:
		$pattern = { 55 8B EC 56 [21] A1 [4] 8B 88 [4] 8B 89 [4] E8 [4] 8B 15 [4] 8B 8A [4] E8 [4] 8B 8E [4] E8 [4] 8B 86 [4] 8B 0D [4] 50 E8 [4] 5E 5D C2 04 00 }
	condition:
		#pattern == 1	
}


//2A0 CRxMgrConfig * mgr_config;
rule CRxApp_mgr_config
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//游戏设定窗口管理器\""
		script = "log \"/*{p:$result}*/    CRxMgrConfig * mgr_config;\""
		script = "$result = @pattern + 0x36 + [@pattern + 0x32]"
		script = "lblset $result, CRxMgrConfig::create"
	strings:
		$pattern = { 68 60 04 00 00 C6 45 ?? 01 E8 [4] 83 C4 04 [26] 53 57 52 51 8B C8 E8 [4] EB ?? 33 C0 89 83 [4] 68 98 06 00 00 }
	condition:
		#pattern == 1	
}

//2A0 CRxMgrMap * mgr_map;
rule CRxApp_mgr_map
{
	meta:
		script = "$result = [@pattern + 0x53]"
		script = "log \"//游戏小地图管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrMap * mgr_map;\""
		script = "$result = @pattern + 0x44 + [@pattern + 0x40]"
		script = "lblset $result, CRxMgrMap::create"
	strings:
		$pattern = { 68 98 06 00 00 C6 45 ?? 01 C6 05 [4] 01 E8 [4] 83 C4 04 [48] 68 60 02 00 00 C6 45 ?? 01 89 83 [4] E8 }
	condition:
		#pattern == 1	
}

//2AC CRxMgrExit * mgr_exit
rule CRxApp_mgr_exit
{
	meta:
		script = "$result = [@pattern + 0x0e]"
		script = "log \"/*{p:$result}*/    CRxMgrExit * mgr_exit;\""
	strings:
		$pattern = { 6A 00 C7 05 [4] 00 00 00 00 8B 80 [4] FF 88 [4] 6A 01 68 31 04 00 00 E8 }
	condition:
		#pattern == 1	
}

//2B0 CRxMgrTask * mgr_task;
rule CRxApp_mgr_task
{
	meta:
		script = "$result = [@pattern + 0x4f]"
		script = "log \"//任务管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrTask * mgr_task;\""
		script = "$result = @pattern + 0x3b + [@pattern + 0x37]"
		script = "lblset $result, CRxMgrTask::create"
	strings:
		$pattern = { 68 6C 06 00 00 C6 45 ?? 01 89 83 [4] E8 [4] 83 C4 04 [40] 68 00 02 00 00 B9 [4] C6 45 ?? 01 89 83 [4] E8 }
	condition:
		#pattern == 1	
}

//2E0 CRxMgrNpc * mgr_npc
rule CRxApp_mgr_npc
{
	meta:
		script = "$result = [@pattern +0x2b]"
		script = "log \"/*{p:$result}*/    CRxMgrNpc * mgr_npc;\""
		
		//script = "$result = [@pattern +0x31]"
		//script = "log \">>>>/*{p:$result}*/    CRxApp::mgr_npc::mgr_strong\""		
	
		//script = "$result = [@pattern +0x37]"
		//script = "log \">>>>>>>>/*{p:$result}*/    CRxApp::mgr_npc::mgr_strong::dlg\""		
				
	strings:
		$pattern = { 68 A1 03 00 00 6A 09 E8 [4] 33 C0 5F 5D C2 10 00 8B 81 [4] 8B 90 [4] 83 7A 40 00 0F 85 [4] 8B 81 [4] 8B 90 [4] 8B 92 }
	condition:
		#pattern == 1		
}

//320 CRxMgrMaker * mgr_maker;
rule CRxApp_mgr_maker
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//制造管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrMaker * mgr_maker;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrMaker::create"
	strings:
		$pattern = { 68 50 13 00 00 [10] E8 [4] 83 C4 04 [26] 68 48 02 00 00 C6 45 ?? 01 89 83 [4] E8 }
	condition:
		#pattern == 1	
}

//324 CRxMgrSweet * mgr_sweet;
rule CRxApp_mgr_sweet
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//情侣管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrSweet * mgr_sweet;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrSweet::create"
	strings:
		$pattern = { 68 48 02 00 00 C6 45 ?? 01 89 83 [4] E8 [4] 83 C4 04 [26] 68 B0 3F 00 00 C6 45 ?? 01 89 83 [4] E8 }
	condition:
		#pattern == 1
}


//328 CRxMgrDrug * mgr_drug; 
rule CRxApp_mgr_drug
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//制药管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrDrug * mgr_drug;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrDrug::create"
	strings:
		$pattern = { 68 B0 3F 00 00 [10] E8 [4] 83 C4 04 [26] 68 48 02 00 00 [10] E8 }
	condition:
		#pattern == 1
}


//32C CRxMgrStrong * mgr_strong_c;
rule CRxApp_mgr_strong_c
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//水晶符强化管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrStrong * mgr_strong_c;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrStrongC::create"
	strings:
		$pattern = { 68 48 02 00 00 [10] E8 [4] 83 C4 04 [26] 68 68 02 00 00 [10] E8 }
	condition:
		#pattern == 1
}


//340 CRxMgrDeath *	mgr_dead;
rule CRxApp_mgr_dead
{
	meta:
		//script = "$result = [@pattern + 0x02]"
		//script = "log \"/*{p:$result}*/    CRxMgrDeath * mgr_dead;\""

		script = "$result = [@pattern + 0x3c]"
		script = "log \"//死亡管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrDeath * mgr_dead;;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrDeath::create"
	strings:
		//$pattern = { 8B [5] 6A 03 6A 01 E8 [17] 6A 02 6A 01 E8 }
		$pattern = { 68 C0 02 00 00 [10] E8 [4] 83 C4 04 [26] 68 D0 03 00 00 [10] E8 }
	condition:
		#pattern == 1
}


//378 CRxMgrPet * mgr_pet;
rule CRxApp_mgr_pet
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//宠物管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrPet * mgr_pet;;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrPet::create"
	strings:
		$pattern = { 68 7C 02 00 00 [10] E8 [4] 83 C4 04 [26] 68 48 02 00 00 [10] E8 }
	condition:
		#pattern == 1
}

//394 CRxMgrTrade * mgr_trad
rule CRxApp_mgr_trad
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//交易管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrTrade * mgr_trad;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrTrade::create"
	strings:
		$pattern = { 68 98 02 00 00 [10] E8 [4] 83 C4 04 [26] 68 60 02 00 00 [10] E8 }
	condition:
		#pattern == 1		
}

//3A8 CRxMgrTeam * mgr_team;
rule CRxApp_mgr_team
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//组队管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrTeam * mgr_team;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrTeam::create"
	strings:
		$pattern = { 68 00 03 00 00 [10] E8 [4] 83 C4 04 [26] 68 34 07 00 00 [10] E8 }
	condition:
		#pattern == 1		
}

//3AC CRxMgrMyShop * mgr_myshop;
rule CRxApp_mgr_myshop
{
	meta:
		script = "$result = [@pattern + 0x4a]"
		script = "log \"//开店管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrMyShop * mgr_myshop;\""
		script = "$result = @pattern + 0x3b + [@pattern + 0x37]"
		script = "lblset $result, CRxMgrMyShop::create"
	strings:
		$pattern = { 68 34 07 00 00 [10] E8 [4] 83 C4 04 [40] 68 BC 04 00 00 [10] E8 }
	condition:
		#pattern == 1		
}

//3B0 CRxMgrTlf * mgr_tlf;
rule CRxApp_mgr_tlf
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//土灵符管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrTlf * mgr_tlf;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrTlf::create"
	strings:
		$pattern = { 68 BC 04 00 00 [10] E8 [4] 83 C4 04 [26] 68 68 04 00 00 [10] E8 }
	condition:
		#pattern == 1		
}


//3b4 CRxMgrCharm * mgr_charm;
rule CRxApp_mgr_charm
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//至尊、热血符管理\""
		script = "log \"/*{p:$result}*/    CRxMgrCharm * mgr_charm;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrCharm::create"
	strings:
		$pattern = { 68 68 04 00 00 [10] E8 [4] 83 C4 04 [26] 68 34 03 00 00 [10] E8 }
	condition:
		#pattern == 1			
}

//3cc CRxMgrMaster * mgr_master;
rule CRxApp_mgr_master
{
	meta:
		script = "$result = [@pattern + 0x67]"
		script = "log \"//师徒管理对象\""
		script = "log \"/*{p:$result}*/    CRxMgrMaster * mgr_master;\""
		script = "$result = @pattern + 0x58 + [@pattern + 0x54]"
		script = "lblset $result, CRxMgrMaster::create"
	strings:
		$pattern = { 68 8C 02 00 00 [53] E8 [4] 83 C4 04 [26] 68 80 02 00 00 C6 45 ?? 01 89 83 [4] E8 }
	condition:
		#pattern == 1
}


//3D0 CRxMgrSkill * mgr_skill;
rule CRxApp_mgr_skill
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//武功栏管理\""
		script = "log \"/*{p:$result}*/    CRxMgrSkill * mgr_skill;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrSkill::create"		
	strings:
		$pattern = { 68 80 02 00 00 [10] E8 [4] 83 C4 04 [26] 68 5C 02 00 00 [10] E8 }
	condition:
		#pattern == 1	
}

//3D4 CRxMgrMakerFrame * mgr_maker_frame;
rule CRxApp_mgr_maker_frame
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"//制造分解窗口的框架窗口\""
		script = "log \"/*{p:$result}*/    CRxMgrMakerFrame * mgr_maker_frame;\""
		script = "$result = @pattern + 0x2d + [@pattern + 0x29]"
		script = "lblset $result, CRxMgrMakerFrame::create"			
	strings:
		$pattern = { 68 5C 02 00 00 [10] E8 [4] 83 C4 04 [26] 68 70 02 00 00 [10] E8 }
	condition:
		#pattern == 1	
}

//C0C int busy
rule CRxApp_busy
{
	meta:
		script = "$result = [@pattern + 0x07]"
		script = "log \"/*{p:$result}*/    int busy;\""
	strings:
		$pattern = { A1 [4] 83 B8 [4] 00 0F 85 [4] C7 80 [4] 01 00 00 00 8B 8E [4] C6 86 [4] 01 88 9E [4] E8 }
	condition:
		#pattern == 1			
}

//C23 char save_name[0x1e][0x0f]
rule CRxApp_save_name
{
	meta:
		script = "$result = [@pattern + 0x09]"
		script = "log \"/*{p:$result}*/    char save_name[0x1e][0x0f];\""
	strings:
		$pattern = { 8B 0D [11] 00 8B 0D [14] 68 53 05 00 00 E8 [4] ?? 68 80 00 00 00 ?? E8 [9] 68 57 04 00 00 E8 }
	condition:
		#pattern == 1			
}

rule CRxApp_end
{
	meta:
		script = "log \"}"
		script = "log"
		script = "log"
	condition:
		true
} 