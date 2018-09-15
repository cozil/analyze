rule CRxStuff_start
{
	meta:
		script = "log \"struct CRxStuff {\""
	condition:
		true
}

//04c int code;
//050 int codeEx;
rule CRxStuff_code
{
	meta:
		script = "$result = byte:[@pattern + 0x02]"
		script = "log \"//物品代码\""
		script = "log \"/*{p:$result}*/    int code;\""
		script = "$result = byte:[@pattern + 0x05]"
		script = "log \"/*{p:$result}*/    int codeEx;\""
	strings:
		$pattern = { 8B 4E ?? 8B 46 ?? 81 F9 09 BC 0D 00 [2] 85 C0 [2] 81 F9 0A BC 0D 00 }
	condition:
		#pattern == 1
}

//054 int s_code1;
//058 int s_code2;
rule CRxStuff_s_code
{
	meta:
		script = "$result = byte:[@pattern + 0x15]"
		script = "log \"/*{p:$result}*/    int s_code1;\""
		script = "$result = byte:[@pattern + 0x12]"
		script = "log \"/*{p:$result}*/    int s_code2;\""
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
		script = "log \"//物品名称\""
		script = "log \"/*{p:$result}*/    char name[0x48];\""
	strings:
		$pattern = { 83 F8 06 0F 84 [4] 83 F8 07 0F 84 [4] 83 F8 08 0F 84 [4] 83 F8 09 75 ?? 8D 46 }
	condition:
		#pattern == 1
}

//0a4 int school;
//0a8 int local_career;
rule CRxStuff_school
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//物品所属派系: 0-无派系 1-正派 2-邪派\""
		script = "log \"/*{p:$result}*/    int school;\""
		script = "$result = [@pattern + 0x33]"
		script = "log \"//物品所属职业\""
		script = "log \"/*{p:$result}*/    int local_career;\""
	strings:
		$pattern = { 8B 87 [12] 83 F8 0B [2] 83 F8 0C [2] 83 F8 0D [2] 83 F8 0E [2] 83 F8 10 [2] 83 F8 11 [2] 83 F8 12 [2] 8B 87 }
	condition:
		#pattern == 1
}

//0ac int grade;
rule CRxStuff_grade
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//装备等级/技能修炼等级\""
		script = "log \"/*{p:$result}*/    int grade;\""
	strings:
		$pattern = { 8B 81 [4] 83 F8 0A [2] 83 F8 23 [2] B8 01 00 00 00 C3 83 F8 3C }
	condition:
		#pattern == 1
}

//0b0 char job;
rule CRxStuff_job
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//武器使用转职级别 1:1转 2:2转 ...\""
		script = "log \"/*{p:$result}*/    char job;\""
	strings:
		$pattern = { 8A 8F [4] 84 C9 [6] 83 F8 03 [2] 80 F9 05 [6] 83 F8 14 }
	condition:
		#pattern == 1
}

//1f2 short list_id;
rule CRxStuff_list_id
{
	meta:
		script = "$result = [@pattern + 0x03]"
		script = "log \"//物品所在列表的索引\""
		script = "log \"/*{p:$result}*/    short list_id;\""
	strings:
		$pattern = { 0F B7 86 [4] 83 F8 07 [2] B9 98 00 00 00 66 3B C1 [2] BA 99 00 00 00 66 3B C2 [2] B9 9B 00 00 00 }
	condition:
		#pattern == 1
}

//1f4 short id;
rule CRxStuff_id
{
	meta:
		script = "$result = [@pattern + 0x03]"
		script = "log \"//物品在物品栏/快捷栏/装备栏/商店等序号\""
		script = "log \"/*{p:$result}*/    short id;\""
	strings:
		$pattern = { 0F B7 88 [4] 83 F9 24 [2] 83 F9 42 [2] 66 83 B8 [4] 01 }
	condition:
		#pattern == 1
}

//1f6 short k_open;
rule CRxStuff_k_open
{
	meta:
		script = "$result = [@pattern + 0x0a]"
		script = "log \"//武功是否已修炼\""
		script = "log \"/*{p:$result}*/    short k_open;\""
	strings:
		$pattern = { 81 7E ?? 77 53 4C 00 66 89 96 [4] B9 0A 00 00 00 [2] 83 7E ?? 00 [2] B9 01 00 00 00 }
	condition:
		#pattern == 1
}

//204 int s_binding;
rule CRxStuff_s_binding
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//物品已捆绑标记\""
		script = "log \"/*{p:$result}*/    int s_binding;\""
	strings:
		$pattern = { 83 BF [4] 00 [6] 8B 0D [4] 68 9C 07 00 00 E8 }
	condition:
		#pattern == 1
}

//22c int s_disable;
//与CRxStuff_s_disable相同
rule CRxStuff_s_disable
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//4个byte分别表示不同的含义，但只要有一个不为0，则物品无法移动\""
		script = "log \"/*{p:$result}*/    int s_disable;\""
	strings:
		$pattern = { 80 BE [4] 00 [2] 83 BE [4] 00 [2] 80 BE [4] 00 [2] 80 BE [4] 00 [2] 80 BE [4] 00 [2] [6] 68 00 00 00 B4 }
	condition:
		#pattern == 1
}

//23c UINT ss_begin;
//244 UINT ss_end;
//24c UINT ss_left;
//254 int ss_running;
rule CRxStuff_ss_begin
{
	meta:
		script = "$result = [@pattern + 0x1b]"
		script = "log \"//物品/技能状态起始时间\""
		script = "log \"/*{p:$result}*/    UINT ss_begin;\""
		script = "$result = [@pattern + 0x41]"
		script = "log \"//物品/技能状态结束时间\""
		script = "log \"/*{p:$result}*/    UINT ss_end;\""
		script = "log"	//连续多个log输出会导致重复输出现象，输出一个空行可解决此问题
		script = "$result = [@pattern + 0x47]"
		script = "log \"//物品/技能状态剩余时间\""
		script = "log \"/*{p:$result}*/    UINT ss_left;\""
		script = "$result = [@pattern + 0x53]"
		script = "log \"//快捷栏技能对象是否正在使用中\""
		script = "log \"/*{p:$result}*/    int ss_running;\""
	strings:
		$pattern = { 83 F8 04 [2] B8 01 00 00 00 89 86 [4] FF 15 [7] 89 86 [4] 8B D0 [3] C7 86 [4] 00 00 00 00 8B BE [8] 89 BE [4] 5F 89 96 [4] 89 86 [4] 89 8E [4] C6 86 [4] 01 }
	condition:
		#pattern == 1
}

//458 int thl_skill_state;
//45c int thl_skill_elapse;
rule CRxStuff_thl_skill
{
	meta:
		script = "$result = [@pattern + 0x08]"
		script = "log \"//仅用于谭花灵职业必杀技能，置0隐藏必杀闪烁图标\""
		script = "log \"/*{p:$result}*/    int thl_skill_state;\""
		script = "$result = [@pattern + 0x02]"
		script = "log \"/*{p:$result}*/    int thl_skill_elapse;\""
	strings:
		$pattern = { 89 86 [4] 8B 86 [4] 83 F8 01 [2] 81 BE [4] C8 00 00 00 [9] 50 8B CE C7 45 ?? 02 00 00 00 E8 }
	condition:
		#pattern == 1
}

//c40 int sex;
rule CRxStuff_sex
{
	meta:
		script = "$result = [@pattern + 0x09]"
		script = "log \"//性别 00:无 01:男 02:女\""
		script = "log \"/*{p:$result}*/    int sex;\""
	strings:
		$pattern = { C6 85 [4] 01 8B 87 [4] 85 C0 [6] 43 83 F8 01 [2] 8B 0D [4] 68 4D 01 00 00 }
	condition:
		#pattern == 1
}

//c44 int count;
//c48 int count_hipart;
rule CRxStuff_count
{
	meta:
		script = "$result = [@pattern + 0x33]"
		script = "log \"//物品数量\""
		script = "log \"/*{p:$result}*/    int count;\""
		script = "$result = [@pattern + 0x24]"
		script = "log \"/*{p:$result}*/    int count_hipart;\""
	strings:
		$pattern = { BA 99 00 00 00 66 3B C2 [2] B9 9B 00 00 00 66 3B C1 [2] BA 9A 00 00 00 66 3B C2 [6] 83 BE [4] 00 [8] 83 BE [4] 00 }
	condition:
		#pattern == 1
}

//c4c int stuff_type;
rule CRxStuff_stuff_type
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//物品类型\""
		script = "log \"/*{p:$result}*/    int stuff_type;\""
	strings:
		$pattern = { 8B 87 [4] 83 F8 01 [2] 83 F8 15 [2] 83 F8 02 [2] 83 F8 04 [2] 83 F8 05 }
	condition:
		#pattern == 1
}

//c94 int bbWearNum;
//c98 int bbWearMax;
rule CRxStuff_bbWearNum
{
	meta:
		script = "$result = [@pattern + 0x1d]"
		script = "log \"//剩余耐久度\""
		script = "log \"/*{p:$result}*/    int bbWearNum;\""
		script = "$result = [@pattern + 0x14]"
		script = "log \"//最大耐久度\""
		script = "log \"/*{p:$result}*/    int bbWearMax;\""
	strings:
		$pattern = { C7 84 9D [4] 05 05 FF FF C6 85 [4] 01 83 BF [4] 00 [2] 8B 87 }
	condition:
		#pattern == 1
}

//ca8 int bbflag;
rule CRxStuff_bbflag
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//百宝物品标志\""
		script = "log \"/*{p:$result}*/    int bbflag;\""
	strings:
		$pattern = { 39 B8 [6] 8B 48 ?? 8B 40 ?? 81 F9 A3 DE 14 3C [2] 3B C7 [2] 81 F9 A4 DE 14 3C }
	condition:
		#pattern == 1
}

//cbc int s_except;
//与CRxStuff_s_disable相同
rule CRxStuff_s_except
{
	meta:
		script = "$result = [@pattern + 0x0b]"
		script = "log \"//物品异常无法使用标记\""
		script = "log \"/*{p:$result}*/    int s_except;\""
	strings:
		$pattern = { 80 BE [4] 00 [2] 83 BE [4] 00 [2] 80 BE [4] 00 [2] 80 BE [4] 00 [2] 80 BE [4] 00 [2] [6] 68 00 00 00 B4 }
	condition:
		#pattern == 1
}


//ccc UINT st_begin;
//cd4 UINT st_end;
//cdc UINT st_left;
rule CRxStuff_st_begin
{
	meta:
		script = "$result = [@pattern + 0x0e]"
		script = "log \"//背包中物品的闪烁控制\""
		script = "log \"/*{p:$result}*/    UINT st_begin;\""
		script = "$result = [@pattern + 0x1d]"
		script = "log \"/*{p:$result}*/    UINT st_end;\""
		script = "$result = [@pattern + 0x2b]"
		script = "log \"/*{p:$result}*/    UINT st_left;\""
	strings:
		$pattern = { FF 15 [4] 89 9E [4] 89 86 [4] 8B 0F 8B 57 04 03 C8 13 D3 89 8E [4] 89 96 [4] 8B 07 89 86 }
	condition:
		#pattern == 1
}

//d2c int stoneType;
rule CRxStuff_stoneType
{
	meta:
		script = "$result = [@pattern + 0x15]"
		script = "log \"//石头类型(若物品是石头) 查看SPT_开头的宏定义\""
		script = "log \"/*{p:$result}*/    int stoneType;\""
	strings:
		$pattern = { 83 BF [4] 15 0F 95 85 [4] E9 [4] 8B 87 [4] 85 C0 0F 84 [4] 83 BF [4] 00 0F 84 [4] 80 BD [4] 00 [2] 83 F8 14 }
	condition:
		#pattern == 1
}


//d34 int propValue;
rule CRxStuff_propValue
{
	meta:
		script = "$result = [@pattern + 0x07]"
		script = "log \"//1.金刚或寒玉石:属性值;2.装备物品：强化次数;3.热血石：类型代码;4:奇玉石：属性与值\""
		script = "log \"/*{p:$result}*/    int propValue;\""
	strings:
		$pattern = { BF 05 05 FF FF 83 BE [4] 00 [6] 80 BD [4] 00 [2] C7 84 9D [4] 55 FF 99 FF }
	condition:
		#pattern == 1
}

//d38 short aditional;					
//d3a short ad_type;
//d3c UINT ad_stage;
rule CRxStuff_aditional
{
	meta:
		script = "$result = [@pattern + 0x03]"
		script = "log \"//附加属性,为1表示存在\""
		script = "log \"/*{p:$result}*/    short aditional;\""
		script = "$result = [@pattern + 0x0d]"
		script = "log \"//附加属性类型 01:火 02:水 03:风 04:内功 05:外功 06:毒\""
		script = "log \"/*{p:$result}*/    short ad_type;\""
		script = "$result = [@pattern + 0x17]"
		script = "log \"//属性阶段 从0开始，表示第1阶段 1表示第2阶段\""
		script = "log \"/*{p:$result}*/    UINT ad_stage;\""
	strings:
		$pattern = { 66 83 BF [4] 01 [2] 66 83 BF [4] 05 [2] 0F BF 87 [4] 8B 8F [4] 51 40 50 6A 05 }
	condition:
		#pattern == 1
}

//d40 _prop prop[4];
rule CRxStuff_prop
{
	meta:
		script = "$result = byte:[@pattern + 0x15]"
		script = "log \"//合成的四个石头属性,每个结构长度为:0x{$result}\""
		script = "$result = [@pattern + 0x09]"		
		script = "log \"/*{p:$result}*/    _prop prop[4];\""
	strings:
		$pattern = { B2 01 B8 01 00 00 00 8D 8F [4] 83 39 02 [2] 40 83 C1 18 83 F8 05 }
	condition:
		#pattern == 1
}

//df0 char s_breaking;
rule CRxStuff_s_breaking
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "log \"//物品分解状态(仅对分解窗口中的物品有效)\""
		script = "log \"/*{p:$result}*/    char s_breaking;\""
	strings:
		$pattern = { 68 C8 C8 C8 64 40 50 51 8D 53 ?? 52 57 8B CE E8 [4] 8A 86 }
	condition:
		#pattern == 1
}

//e1a char advflag;
//e1c short advcode;
//e32 short soul;
rule CRxStuff_advflag
{
	meta:
		script = "$result = [@pattern + 0x3a]"
		script = "log \"//奇玉石属性标记\""
		script = "log \"/*{p:$result}*/    char advflag;\""
		script = "$result = [@pattern + 0x53]"
		script = "log \"//奇玉石代码\""
		script = "log \"/*{p:$result}*/    short advcode;\""
		script = "$result = [@pattern + 0x21]"
		script = "log \"//灵魂阶段 0-5\""
		script = "log \"/*{p:$result}*/    short advcode;\""
	strings:
		//F6 87 [4] 01 0F 85 [4] 8B CB C1 E1 09 8D B4 0D [4] BA 05 00 00 00 8D 8F [25] 83 F9 01
		$pattern = { 81 ?? AD DF 14 3C [12] 81 ?? B0 DF 14 3C [6] 0F B7 87 [4] C7 85 [4] 00 00 00 00 [9] F6 87 [4] 01 [17] 0F B7 8F }
	condition:
		#pattern == 1
}

//e38 int level;
rule CRxStuff_level
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//进化等级\""
		script = "log \"/*{p:$result}*/    int level;\""
	strings:
		$pattern = { 8B 86 [4] 48 74 ?? 48 75 ?? 8B 0D [4] 68 6E 0A 00 00 E8 }
	condition:
		#pattern == 1
}


//e40 int lock_time;
//e44 int locked;
rule CRxStuff_lock_time
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"//锁定时间与标记\""
		script = "log \"/*{p:$result}*/    int lock_time;\""
		script = "$result = [@pattern + 0x72]"
		script = "log \"/*{p:$result}*/    int locked;\""
	strings:
		$pattern = { 83 BF [4] 00 [20] 7B [4] 01 [4] 08 [4] 09 [4] 0D [3] 8A 00 00 00 [7] 3B [4] 3C [44] 03 b7 }
	condition:
		#pattern == 1
}

rule CRxStuff_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}