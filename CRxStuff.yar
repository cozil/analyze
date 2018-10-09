rule CRxStuff_start
{
	meta:
		script = "Type.as CRxStuff"
		script = "Type.aanc CRxStuff,CRxObject"
		script = "Type.comment CRxStuff,\"物品管理\""
		script = "Type.ad CRxStuff,\"inline bool is_disable_select() const {{ return (s_disable || s_except); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_disable_trade() const {{ return (is_disable_select() || s_binding || locked); }}\""
		
		script = "Type.ad CRxStuff,\"inline bool is_career_knife() const {{ return (local_career == LocalCareerKnife); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_career_sword() const {{ return (local_career == LocalCareerSword); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_career_spear() const {{ return (local_career == LocalCareerSpear); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_career_bow() const {{ return (local_career == LocalCareerBow || local_career == LocalCareerMnz); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_career_doctor() const {{ return (local_career == LocalCareerDoctor); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_career_stabber() const {{ return (local_career == LocalCareerStabber); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_career_musician() const {{ return (local_career == LocalCareerMusician); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_career_hfg() const {{ return (local_career == LocalCareerHfg); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_career_thl() const {{ return (local_career == LocalCareerThl); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_career_fister() const {{ return (local_career == LocalCareerFister); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_career_mnz() const {{ return (local_career == LocalCareerMnz); }}\""
		script = "Type.ad CRxStuff,\"inline bool is_career_lfl() const {{ return (local_career == LocalCareerLfl); }}\""
		
		script = "Type.ad CRxStuff,\"inline bool is_stone_full() const {{ return ((stuff_type == ST_SHELL && prop[1].value != 0) || (prop[_countof(prop) - 1].value != 0)); }}\""
		
		script = "Type.ad CRxStuff,\"uint32_t get_stone_num() const;\""
		script = "Type.ad CRxStuff,\"bool is_sortofstone() const;\""
		script = "Type.ad CRxStuff,\"bool is_money() const;\""
	condition:
		true
}

//04c uint64_t code;
rule CRxStuff_code
{
	meta:
		script = "$result = byte:[@pattern + 0x02]"
		script = "Type.am CRxStuff,uint64_t,code,0,$result"
		script = "Type.mcomment CRxStuff,code,\"物品代码\""
	strings:
		$pattern = { 8B 4E ?? 8B 46 ?? 81 F9 09 BC 0D 00 [2] 85 C0 [2] 81 F9 0A BC 0D 00 }
	condition:
		#pattern == 1
}

//054 uint64_t s_code;
rule CRxStuff_s_code
{
	meta:
		script = "$result = byte:[@pattern + 0x15]"
		script = "Type.am CRxStuff,uint64_t,s_code,0,$result"
	strings:
		$pattern = { 83 BE [4] 02 [2] C6 86 [4] 01 8B 46 ?? 8B 4E ?? 50 51 E8 [4] 83 C4 08 3C 01 }
	condition:
		#pattern == 1
}

//05c char name[0x48];
rule CRxStuff_name
{
	meta:
		script = "$result = byte:[@pattern + 0x22]"
		script = "Type.am CRxStuff,char,name,0x48,$result"
		script = "Type.mcomment CRxStuff,name,\"物品名称\""
	strings:
		$pattern = { 83 F8 06 0F 84 [4] 83 F8 07 0F 84 [4] 83 F8 08 0F 84 [4] 83 F8 09 75 ?? 8D 46 }
	condition:
		#pattern == 1
}

//0a4 uint32_t school;
//0a8 uint32_t local_career;
rule CRxStuff_school
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxStuff,uint32_t,school,0,$result"
		script = "Type.mcomment CRxStuff,school,\"物品所属派系: 0-无派系 1-正派 2-邪派\""
		script = "$result = [@pattern + 0x33]"
		script = "Type.am CRxStuff,uint32_t,local_career,0,$result"
		script = "Type.mcomment CRxStuff,local_career,\"物品所属职业\""
	strings:
		$pattern = { 8B 87 [12] 83 F8 0B [2] 83 F8 0C [2] 83 F8 0D [2] 83 F8 0E [2] 83 F8 10 [2] 83 F8 11 [2] 83 F8 12 [2] 8B 87 }
	condition:
		#pattern == 1
}

//0ac uint32_t grade;
rule CRxStuff_grade
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxStuff,uint32_t,grade,0,$result"
		script = "Type.mcomment CRxStuff,grade,\"装备等级/技能修炼等级\""
	strings:
		$pattern = { 8B 81 [4] 83 F8 0A [2] 83 F8 23 [2] B8 01 00 00 00 C3 83 F8 3C }
	condition:
		#pattern == 1
}

//0b0 uint8_t job;
rule CRxStuff_job
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxStuff,uint8_t,job,0,$result"
		script = "Type.mcomment CRxStuff,job,\"武器使用转职级别 1:1转 2:2转 ...\""
	strings:
		$pattern = { 8A 8F [4] 84 C9 [6] 83 F8 03 [2] 80 F9 05 [6] 83 F8 14 }
	condition:
		#pattern == 1
}

//1f2 uint16_t list_id;
rule CRxStuff_list_id
{
	meta:
		script = "$result = [@pattern + 0x03]"
		script = "Type.am CRxStuff,uint16_t,list_id,0,$result"
		script = "Type.mcomment CRxStuff,list_id,\"物品所在列表的索引\""
	strings:
		$pattern = { 0F B7 86 [4] 83 F8 07 [2] B9 98 00 00 00 66 3B C1 [2] BA 99 00 00 00 66 3B C2 [2] B9 9B 00 00 00 }
	condition:
		#pattern == 1
}

//1f4 uint16_t id;
rule CRxStuff_id
{
	meta:
		script = "$result = [@pattern + 0x03]"
		script = "Type.am CRxStuff,uint16_t,id,0,$result"
		script = "Type.mcomment CRxStuff,id,\"物品在物品栏/快捷栏/装备栏/商店等序号\""
	strings:
		$pattern = { 0F B7 88 [4] 83 F9 24 [2] 83 F9 42 [2] 66 83 B8 [4] 01 }
	condition:
		#pattern == 1
}

//1f6 uint16_t k_open;
rule CRxStuff_k_open
{
	meta:
		script = "$result = [@pattern + 0x0a]"
		script = "Type.am CRxStuff,uint16_t,k_open,0,$result"
		script = "Type.mcomment CRxStuff,k_open,\"武功是否已修炼\""
	strings:
		$pattern = { 81 7E ?? 77 53 4C 00 66 89 96 [4] B9 0A 00 00 00 [2] 83 7E ?? 00 [2] B9 01 00 00 00 }
	condition:
		#pattern == 1
}

//204 uint32_t s_binding;
rule CRxStuff_s_binding
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxStuff,uint32_t,s_binding,0,$result"
		script = "Type.mcomment CRxStuff,s_binding,\"物品已捆绑标记\""
	strings:
		$pattern = { 83 BF [4] 00 [6] 8B 0D [4] 68 9C 07 00 00 E8 }
	condition:
		#pattern == 1
}

//22c uint32_t s_disable;
rule CRxStuff_s_disable
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxStuff,uint32_t,s_disable,0,$result"
		script = "Type.mcomment CRxStuff,s_disable,\"4个byte分别表示不同的含义，但只要有一个不为0，则物品无法移动\""
	strings:
		$pattern = { 80 BE [4] 00 [2] 83 BE [4] 00 [2] 80 BE [4] 00 [2] 80 BE [4] 00 [2] 80 BE [4] 00 [2] [6] 68 00 00 00 B4 }
	condition:
		#pattern == 1
}

//23c uint32_t ss_begin;
//244 uint32_t ss_end;
//24c uint32_t ss_left;
//254 uint32_t ss_running;
rule CRxStuff_ss_begin
{
	meta:
		script = "$result = [@pattern + 0x1b]"
		script = "Type.am CRxStuff,uint32_t,ss_begin,0,$result"
		script = "Type.mcomment CRxStuff,ss_begin,\"物品/技能状态起始时间\""
		script = "$result = [@pattern + 0x41]"
		script = "Type.am CRxStuff,uint32_t,ss_end,0,$result"
		script = "Type.mcomment CRxStuff,ss_end,\"物品/技能状态结束时间\""
		
		script = "$result = [@pattern + 0x47]"
		script = "Type.am CRxStuff,uint32_t,ss_left,0,$result"
		script = "Type.mcomment CRxStuff,ss_left,\"物品/技能状态剩余时间\""
		script = "$result = [@pattern + 0x53]"
		script = "Type.am CRxStuff,uint32_t,ss_running,0,$result"
		script = "Type.mcomment CRxStuff,ss_running,\"物品/快捷栏技能对象是否正在使用中\""
	strings:
		$pattern = { 83 F8 04 [2] B8 01 00 00 00 89 86 [4] FF 15 [7] 89 86 [4] 8B D0 [3] C7 86 [4] 00 00 00 00 8B BE [8] 89 BE [4] 5F 89 96 [4] 89 86 [4] 89 8E [4] C6 86 [4] 01 }
	condition:
		#pattern == 1
}

//458 uint32_t thl_skill_state;
//45c uint32_t thl_skill_elapse;
rule CRxStuff_thl_skill
{
	meta:
		script = "$result = [@pattern + 0x08]"
		script = "Type.am CRxStuff,uint32_t,thl_skill_state,0,$result"
		script = "Type.mcomment CRxStuff,thl_skill_state,\"仅用于谭花灵职业必杀技能，置0隐藏必杀闪烁图标\""
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxStuff,uint32_t,thl_skill_elapse,0,$result"
	strings:
		$pattern = { 89 86 [4] 8B 86 [4] 83 F8 01 [2] 81 BE [4] C8 00 00 00 [9] 50 8B CE C7 45 ?? 02 00 00 00 E8 }
	condition:
		#pattern == 1
}

//c40 uint32_t sex;
rule CRxStuff_sex
{
	meta:
		script = "$result = [@pattern + 0x09]"
		script = "Type.am CRxStuff,uint32_t,sex,0,$result"
		script = "Type.mcomment CRxStuff,sex,\"性别 00:无 01:男 02:女\""
	strings:
		$pattern = { C6 85 [4] 01 8B 87 [4] 85 C0 [6] 43 83 F8 01 [2] 8B 0D [4] 68 4D 01 00 00 }
	condition:
		#pattern == 1
}

//c44 uint64_t count;
rule CRxStuff_count
{
	meta:
		script = "$result = [@pattern + 0x33]"
		script = "Type.am CRxStuff,uint64_t,count,0,$result"
		script = "Type.mcomment CRxStuff,count,\"物品数量\""
	strings:
		$pattern = { BA 99 00 00 00 66 3B C2 [2] B9 9B 00 00 00 66 3B C1 [2] BA 9A 00 00 00 66 3B C2 [6] 83 BE [4] 00 [8] 83 BE [4] 00 }
	condition:
		#pattern == 1
}

//c4c uint32_t stuff_type;
rule CRxStuff_stuff_type
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxStuff,uint32_t,stuff_type,0,$result"
		script = "Type.mcomment CRxStuff,stuff_type,\"物品类型\""
	strings:
		$pattern = { 8B 87 [4] 83 F8 01 [2] 83 F8 15 [2] 83 F8 02 [2] 83 F8 04 [2] 83 F8 05 }
	condition:
		#pattern == 1
}

//c94 uint32_t bbWearNum;
//c98 uint32_t bbWearMax;
rule CRxStuff_bbWearNum
{
	meta:
		script = "$result = [@pattern + 0x1d]"
		script = "Type.am CRxStuff,uint32_t,bbWearNum,0,$result"
		script = "Type.mcomment CRxStuff,bbWearNum,\"剩余耐久度\""
		script = "$result = [@pattern + 0x14]"
		script = "Type.am CRxStuff,uint32_t,bbWearMax,0,$result"
		script = "Type.mcomment CRxStuff,bbWearMax,\"最大耐久度\""
	strings:
		$pattern = { C7 84 9D [4] 05 05 FF FF C6 85 [4] 01 83 BF [4] 00 [2] 8B 87 }
	condition:
		#pattern == 1
}

//ca8 uint32_t bbflag;
rule CRxStuff_bbflag
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxStuff,uint32_t,bbflag,0,$result"
		script = "Type.mcomment CRxStuff,bbflag,\"百宝物品标志\""
	strings:
		$pattern = { 39 B8 [6] 8B 48 ?? 8B 40 ?? 81 F9 A3 DE 14 3C [2] 3B C7 [2] 81 F9 A4 DE 14 3C }
	condition:
		#pattern == 1
}

//cbc uint32_t s_except;
//与CRxStuff_s_disable相同
rule CRxStuff_s_except
{
	meta:
		script = "$result = [@pattern + 0x0b]"
		script = "Type.am CRxStuff,uint32_t,s_except,0,$result"
		script = "Type.mcomment CRxStuff,s_except,\"物品异常无法使用标记\""
	strings:
		$pattern = { 80 BE [4] 00 [2] 83 BE [4] 00 [2] 80 BE [4] 00 [2] 80 BE [4] 00 [2] 80 BE [4] 00 [2] [6] 68 00 00 00 B4 }
	condition:
		#pattern == 1
}

//ccc uint32_t st_begin;
//cd4 uint32_t st_end;
//cdc uint32_t st_left;
rule CRxStuff_st_begin
{
	meta:
		script = "$result = [@pattern + 0x0e]"
		script = "Type.am CRxStuff,uint32_t,st_begin,0,$result"
		script = "$result = [@pattern + 0x1d]"
		script = "Type.am CRxStuff,uint32_t,st_end,0,$result"
		script = "$result = [@pattern + 0x2b]"
		script = "Type.am CRxStuff,uint32_t,st_left,0,$result"
		script = "Type.mcomment CRxStuff,st_begin,\"背包中物品的闪烁控制\""
	strings:
		$pattern = { FF 15 [4] 89 9E [4] 89 86 [4] 8B 0F 8B 57 04 03 C8 13 D3 89 8E [4] 89 96 [4] 8B 07 89 86 }
	condition:
		#pattern == 1
}

//d2c uint32_t stoneType;
rule CRxStuff_stoneType
{
	meta:
		script = "$result = [@pattern + 0x15]"
		script = "Type.am CRxStuff,uint32_t,stoneType,0,$result"
		script = "Type.mcomment CRxStuff,stoneType,\"石头类型(若物品是石头) 查看SPT_开头的宏定义\""
	strings:
		$pattern = { 83 BF [4] 15 0F 95 85 [4] E9 [4] 8B 87 [4] 85 C0 0F 84 [4] 83 BF [4] 00 0F 84 [4] 80 BD [4] 00 [2] 83 F8 14 }
	condition:
		#pattern == 1
}


//d34 uint32_t propValue;
rule CRxStuff_propValue
{
	meta:
		script = "$result = [@pattern + 0x07]"
		script = "Type.am CRxStuff,uint32_t,propValue,0,$result"
		script = "Type.mcomment CRxStuff,propValue,\"1.金刚或寒玉石:属性值;2.装备物品：强化次数;3.热血石：类型代码;4:奇玉石：属性与值\""
	strings:
		$pattern = { BF 05 05 FF FF 83 BE [4] 00 [6] 80 BD [4] 00 [2] C7 84 9D [4] 55 FF 99 FF }
	condition:
		#pattern == 1
}

//d38 uint16_t aditional;					
//d3a uint16_t ad_type;
//d3c uint32_t ad_stage;
rule CRxStuff_aditional
{
	meta:
		script = "$result = [@pattern + 0x03]"
		script = "Type.am CRxStuff,uint16_t,aditional,0,$result"
		script = "Type.mcomment CRxStuff,aditional,\"附加属性,为1表示存在\""
		script = "$result = [@pattern + 0x0d]"
		script = "Type.am CRxStuff,uint16_t,ad_type,0,$result"
		script = "Type.mcomment CRxStuff,ad_type,\"附加属性类型 01:火 02:水 03:风 04:内功 05:外功 06:毒\""
		script = "$result = [@pattern + 0x17]"
		script = "Type.am CRxStuff,uint32_t,ad_stage,0,$result"
		script = "Type.mcomment CRxStuff,ad_stage,\"属性阶段 从0开始，表示第1阶段 1表示第2阶段\""
	strings:
		$pattern = { 66 83 BF [4] 01 [2] 66 83 BF [4] 05 [2] 0F BF 87 [4] 8B 8F [4] 51 40 50 6A 05 }
	condition:
		#pattern == 1
}

//d40 StuffProp prop[4];
rule CRxStuff_prop
{
	meta:
		script = "$result1 = byte:[@pattern + 0x15]"
		script = "$result = [@pattern + 0x09]"		
		script = "Type.am CRxStuff,StuffProp,prop,4,$result"
		script = "Type.mcomment CRxStuff,prop,\"合成的四个石头属性,每个结构长度为:0x{$result1}\""
	strings:
		$pattern = { B2 01 B8 01 00 00 00 8D 8F [4] 83 39 02 [2] 40 83 C1 18 83 F8 05 }
	condition:
		#pattern == 1
}

//df0 uint8_t s_breaking;
rule CRxStuff_s_breaking
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "Type.am CRxStuff,uint8_t,s_breaking,0,$result"
		script = "Type.mcomment CRxStuff,s_breaking,\"物品分解状态(仅对分解窗口中的物品有效)\""
	strings:
		$pattern = { 68 C8 C8 C8 64 40 50 51 8D 53 ?? 52 57 8B CE E8 [4] 8A 86 }
	condition:
		#pattern == 1
}

//e1a uint8_t advflag;
//e1c uint16_t advcode;
//e32 uint16_t soul;
rule CRxStuff_advflag
{
	meta:
		script = "$result = [@pattern + 0x3a]"
		script = "Type.am CRxStuff,uint8_t,advflag,0,$result"
		script = "Type.mcomment CRxStuff,advflag,\"奇玉石属性标记\""
		script = "$result = [@pattern + 0x53]"
		script = "Type.am CRxStuff,uint16_t,advcode,0,$result"
		script = "Type.mcomment CRxStuff,advcode,\"奇玉石代码\""
		script = "$result = [@pattern + 0x21]"
		script = "Type.am CRxStuff,uint16_t,soul,0,$result"
		script = "Type.mcomment CRxStuff,soul,\"灵魂阶段 0-5\""
	strings:
		$pattern = { 81 ?? AD DF 14 3C [12] 81 ?? B0 DF 14 3C [6] 0F B7 87 [4] C7 85 [4] 00 00 00 00 [9] F6 87 [4] 01 [17] 0F B7 8F }
	condition:
		#pattern == 1
}

//e38 uint32_t level;
rule CRxStuff_level
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxStuff,uint32_t,level,0,$result"
		script = "Type.mcomment CRxStuff,level,\"进化等级\""
	strings:
		$pattern = { 8B 86 [4] 48 74 ?? 48 75 ?? 8B 0D [4] 68 6E 0A 00 00 E8 }
	condition:
		#pattern == 1
}


//e40 uint32_t lock_time;
//e44 uint32_t locked;
rule CRxStuff_lock_time
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxStuff,uint32_t,lock_time,0,$result"
		script = "Type.mcomment CRxStuff,lock_time,\"锁定时间与标记\""
		script = "$result = [@pattern + 0x72]"
		script = "Type.am CRxStuff,uint32_t,locked,0,$result"
	strings:
		$pattern = { 83 BF [4] 00 [20] 7B [4] 01 [4] 08 [4] 09 [4] 0D [3] 8A 00 00 00 [7] 3B [4] 3C [44] 03 b7 }
	condition:
		#pattern == 1
}

rule CRxStuff_end
{
	meta:
		script = "Type.print CRxStuff,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}