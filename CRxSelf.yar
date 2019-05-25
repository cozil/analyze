
//
//CRxSelf部分成员偏移分析
//


rule CRxSelf_start
{
	meta:
		script = "Type.as CRxSelf"
		script = "Type.am CRxSelf,char,name,0xf,0"
		script = "Type.mcomment CRxSelf,name,\"角色名称\""
		script = "Type.ad CRxSelf,\"inline bool is_dead() const {{ return (life == 0 || action == 2); }}\""
		script = "Type.ad CRxSelf,\"inline uint32_t get_life_percent() const {{ return (life * 100 / maxLife); }}\""
		script = "Type.ad CRxSelf,\"inline uint32_t get_energy_percent() const {{ return (energy * 100 / maxEnergy); }}\""
		script = "Type.ad CRxSelf,\"inline uint32_t get_exp_percent() const {{ return (uint32_t)(exp * 100 / maxExp); }}\""
		script = "Type.ad CRxSelf,\"inline uint32_t get_mnzzl_percent() const {{ return (mnz_zl_max != 0) ? (mnz_zl * 100 / mnz_zl_max) : 0; }}\""
		script = "Type.ad CRxSelf,\"inline uint32_t get_weight_percent() const {{ return (uint32_t)((weight * 100 / max_weight) + ((((weight * 100) % max_weight) != 0) ? 1 : 0)); }}\""
		script = "Type.ad CRxSelf,\"inline uint32_t get_stand_percent() const {{ return (stand * 100 / maxStand); }}\""
		
		script = "Type.ad CRxSelf,\"inline bool is_career_knife() const {{ return (local_career == LocalCareerKnife); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_career_sword() const {{ return (local_career == LocalCareerSword); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_career_spear() const {{ return (local_career == LocalCareerSpear); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_career_bow() const {{ return (local_career == LocalCareerBow || local_career == LocalCareerMnz); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_career_doctor() const {{ return (local_career == LocalCareerDoctor); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_career_stabber() const {{ return (local_career == LocalCareerStabber); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_career_musician() const {{ return (local_career == LocalCareerMusician); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_career_hfg() const {{ return (local_career == LocalCareerHfg); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_career_thl() const {{ return (local_career == LocalCareerThl); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_career_fister() const {{ return (local_career == LocalCareerFister); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_career_mnz() const {{ return (local_career == LocalCareerMnz); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_career_lfl() const {{ return (local_career == LocalCareerLfl); }}\""
		script = "Type.ad CRxSelf,\"inline bool is_farattack_career() const {{ return (is_career_doctor() || is_career_bow() || is_career_musician()); }}\""
		script = "Type.ad CRxSelf,\"uint32_t get_career_mask() const;\""
	condition:
		true
}

//000f uint8_t sex;
rule CRxSelf_sex
{
	meta:
		script = "$result = [@pattern + 0x18]"
		script = "lblset $result, CRxSelf::sex"
		script = "Type.am CRxSelf,uint8_t,sex,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,sex,\"性别\""
	strings:
		$pattern = { 83 F9 11 [2] 83 F9 12 [2] 80 E9 05 [4] 06 88 48 ?? 0F B6 0D }
	condition:
		#pattern == 1			
}

//0014 char school[0x10];
rule CRxSelf_school
{
	meta:
		script = "$result = [@pattern + 0x1]"
		script = "lblset $result, CRxSelf::school"
		script = "Type.am CRxSelf,char,school,0x10,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,school,\"门派\""
	strings:
		$pattern = { B8 [47] FF [11] 7F 7F 7F FF [2] 39 EF FF FF  }
		
	condition:
		#pattern == 1			
}

//002c uint32_t group;
rule CRxSelf_group
{
	meta:
		script = "$result = [@pattern + 0x9]"
		script = "lblset $result, CRxSelf::group"
		script = "Type.am CRxSelf,uint32_t,group,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,group,\"0:无派 1:正派 2:邪派\""
	strings:
		$pattern = { 81 FA 21 03 00 00 [2] A1 [6] 5A 3C 00 00 [4] 5B 3C 00 00 }
	condition:
		#pattern == 1			
}


//0030 uint32_t local_career;
rule CRxSelf_local_career
{
	meta:
		script = "$result = [@pattern + 0xb]"
		script = "lblset $result, CRxSelf::local_career"
		script = "Type.am CRxSelf,uint32_t,local_career,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,local_career,\"职业\""
	strings:
		$pattern = { 05 D4 00 00 00 [4] 83 3D [4] 0E 68 [6] 68 6A 12 00 00 }
	condition:
		#pattern == 1			
}

//0034 uint8_t grade;
rule CRxSelf_grade
{
	meta:
		script = "$result = [@pattern + 0x13]"
		script = "lblset $result, CRxSelf::grade"
		script = "Type.am CRxSelf,uint8_t,grade,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,grade,\"等级\""
	strings:
		$pattern = { 83 FF 12 [4] 22 [4] E8 [4] 80 3D [4] 50 [4] 21 }
	condition:
		#pattern == 1			
}

//0035 uint8_t job;
rule CRxSelf_job
{
	meta:
		script = "$result = [@pattern + 0x13]"
		script = "lblset $result, CRxSelf::job"
		script = "Type.am CRxSelf,uint8_t,job,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,job,\"转职次数0,1,2,3,4,…\""
	strings:
		$pattern = { 68 E4 08 00 00 6A 04 E8 [9] 8A 0D [4] 57 [2] 01 [4] 03 [4] 02 [4] 03 }
	condition:
		#pattern == 1			
}

//007d uint8_t action;
rule CRxSelf_action
{
	meta:
		script = "$result = [@pattern + 0x4]"
		script = "lblset $result, CRxSelf::action"
		script = "Type.am CRxSelf,uint8_t,action,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,action,\"action=2表示玩家死亡\""
	strings:
		$pattern = { 8A 46 06 A2 [4] 8B 56 0A }
	condition:
		#pattern == 1			
}

//0080 uint32_t life;
//008c uint32_t maxLife;
rule CRxSelf_life
{
	meta:
		script = "$result = [@pattern + 0xe]"
		script = "lblset $result, CRxSelf::life"
		script = "Type.am CRxSelf,uint32_t,life,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,life,\"生命值\""
		
		script = "$result = [@pattern + 0x14]"
		script = "lblset $result, CRxSelf::maxLife"
		script = "Type.am CRxSelf,uint32_t,maxLife,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,maxLife,\"最大生命值\""
	strings:
		$pattern = { 83 C6 04 83 F8 02 0F 8E [4] DB 05 [4] DA 35 }
	condition:
		#pattern == 1			
}

//0084 uint32_t energy;
//0090 uint32_t maxEnergy;
rule CRxSelf_energy
{
	meta:
		script = "$result = [@pattern + 0xe]"
		script = "lblset $result, CRxSelf::energy"
		script = "Type.am CRxSelf,uint32_t,energy,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,energy,\"能量\""
		
		script = "$result = [@pattern + 0x14]"
		script = "lblset $result, CRxSelf::maxEnergy"
		script = "Type.am CRxSelf,uint32_t,maxEnergy,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,maxEnergy,\"最大能量\""
	strings:
		$pattern = { 83 C6 04 83 F8 04 0F 8E [4] DB 05 [4] DA 35 }
	condition:
		#pattern == 1			
}

//0088 uint32_t stand;
//0094 uint32_t maxStand;
rule CRxSelf_stand
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "lblset $result, CRxSelf::stand"
		script = "Type.am CRxSelf,uint32_t,stand,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,stand,\"持久\""
		
		script = "$result = [@pattern + 0x15]"
		script = "lblset $result, CRxSelf::maxStand"
		script = "Type.am CRxSelf,uint32_t,maxStand,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,maxStand,\"最大持久\""
	strings:
		$pattern = { 83 3D [4] 05 [2] 33 FF 89 3D [6] 8B 3D [4] 8B 8E [4] 85 C9 74 ?? 85 FF 74 ?? A1 [4] 6B C0 64 }
	condition:
		#pattern == 1			
}


//0098 uint64_t exp;
//00a0 uint64_t maxExp;
rule CRxSelf_exp
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "lblset $result, CRxSelf::exp"
		script = "Type.am CRxSelf,uint64_t,exp,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,exp,\"经验值\""
		
		script = "$result = [@pattern + 0xf]"		
		script = "lblset $result, CRxSelf::maxExp"
		script = "Type.am CRxSelf,uint64_t,maxExp,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,maxExp,\"下次升级经验值\""
	strings:
		$pattern = { DF 2D [5] DC 0D [4] DF 2D [4] DE F9 D9 5D ?? D9 45 ?? D9 1C 24 }
	condition:
		#pattern == 1			
}

//00ac uint32_t trains;
rule CRxSelf_trains
{
	meta:
		script = "$result = [@pattern + 0x20]"
		script = "lblset $result, CRxSelf::trains"
		script = "Type.am CRxSelf,uint32_t,trains,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,trains,\"历练值\""
	strings:
		$pattern = { 68 04 01 00 00 E9 [4] 68 D2 07 00 00 EB ?? 68 55 11 00 00 EB ?? 8B B6 [4] 89 35 }
	condition:
		#pattern == 1			
}

//00c0 int wx;
rule CRxSelf_wx
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "lblset $result, CRxSelf::wx"
		script = "Type.am CRxSelf,int,wx,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,wx,\"武勋值\""
	strings:
		$pattern = { 6A 00 6A 01 6A 01 75 ?? 68 6B 11 00 00 EB ?? 8B 15 [4] A1 }
	condition:
		#pattern == 1			
}

//00e4 uint64_t money;
rule CRxSelf_money
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "lblset $result, CRxSelf::money"
		script = "Type.am CRxSelf,uint64_t,money,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,money,\"背包金钱\""
	strings:
		$pattern = { 81 3D [8] 76 ?? 8B 0D [4] 68 76 01 00 00 6A 09 }
	condition:
		#pattern == 1			
}

//00ec uint16_t weight;
//00ee uint16_t max_weight;
rule CRxSelf_max_weight
{
	meta:
		script = "$result = [@pattern + 0x18]"
		script = "lblset $result, CRxSelf::weight"
		script = "Type.am CRxSelf,uint16_t,weight,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,weight,\"当前物品重量\""
		
		script = "$result = [@pattern + 0x22]"
		script = "lblset $result, CRxSelf::max_weight"
		script = "Type.am CRxSelf,uint16_t,max_weight,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,max_weight,\"最大承受重量\""
	strings:
		$pattern = { 68 00 00 FF FA [2] 68 E4 F9 9E C8 E8 [8] 66 89 0D [8] 66 A3 }
	condition:
		#pattern == 1			
}

//00f0 uint16_t point
rule CRxSelf_point
{
	meta:
		script = "$result = [@pattern + 0x11]"
		script = "lblset $result, CRxSelf::point"
		script = "Type.am CRxSelf,uint16_t,point,0,$result - RoleInfo\""
		script = "Type.mcomment CRxSelf,point,\"可用气功点数\""
	strings:
		$pattern = { 51 68 [4] 6A 0A 8D 55 ?? 52 EB ?? 0F BF 05 [4] 50 68 [4] 6A 0A }
	condition:
		#pattern == 1			
}

//2cee uint16_t wx_quota
//2cf0 uint16_t wx_lose
rule CRxSelf_wx_quota
{
	meta:
		script = "$result = [@pattern + 0x9]"
		script = "lblset $result, CRxSelf::wx_quota"
		script = "Type.am CRxSelf,uint16_t,wx_quota,0,$result - RoleInfo"
		script = "Type.mcomment CRxSelf,wx_quota,\"当日武勋配额\""
		
		script = "$result = [@pattern + 0x17]"
		script = "lblset $result, CRxSelf::wx_lose"
		script = "Type.am CRxSelf,uint16_t,wx_lose,0,$result - RoleInfo"	
		script = "Type.mcomment CRxSelf,wx_lose,\"当日因击杀丢失的武勋\""
		
	strings:
		//特征码中的偏移值为通讯封包结构成员
		$pattern = { 0F [2] 2C 04 00 00 66 [5] 0F [2] 2E 04 00 00 66 }
	condition:
		#pattern == 1			
}

//2d04 uint32_t mnz_zl
//2d08 uint32_t mnz_zl_max

rule CRxSelf_mnz_zl
{
	meta:
		script = "$result = [@pattern + 0x22]"
		script = "lblset $result, CRxSelf::mnz_zl"
		script = "Type.am CRxSelf,uint32_t,mnz_zl,0,$result - RoleInfo"
		script = "Type.mcomment CRxSelf,mnz_zl,\"梅柳真：障力值\""
		
		script = "$result = [@pattern + 0x19]"
		script = "lblset $result, CRxSelf::mnz_zl_max"
		script = "Type.am CRxSelf,uint32_t,mnz_zl_max,0,$result - RoleInfo"		
		script = "Type.mcomment CRxSelf,mnz_zl_max,\"梅柳真：障力值上限\""
	strings:
		$pattern = { 83 3D [4] 11 56 57 8B F1 75 ?? 8B 8E [4] 85 C9 74 ?? 8B 3D [4] 85 FF 74 ?? A1 [4] 6B C0 64 99 F7 FF 50 E8 }
	condition:
		#pattern == 1	
}

rule CRxSelf_end
{
	meta:
		script = "Type.print CRxSelf,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
