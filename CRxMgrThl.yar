rule CRxMgrThl_start
{
	meta:
		script = "Type.as CRxMgrThl"
		script = "Type.aanc CRxMgrThl,CRxMgr"
		script = "Type.comment CRxMgrThl,\"谭花灵必杀管理\""
	condition:
		true
}

//230 uint32_t pkskills[3];
rule CRxMgrThl_pkskills
{
	meta:
		script = "$result = [@pattern + 0x1a]"
		script = "Type.am CRxMgrThl,uint32_t,pkskills,3,$result"
	strings:
	
		//函数第一个引用位置在CRxMgrThl的构造函数中
		//查看对ThlAttackMgr赋值的引用，即可找到构造函数
	
		$pattern = {  C7 45 ?? 1F 00 00 00 C6 45 ?? 00 85 DB 0F 8E [4] BA 11 86 1E 00 8D BE}
	condition:
		#pattern == 1
}
 
//23c uint32_t skills[6];
rule CRxMgrThl_skills
{
	meta:
		script = "$result = [@pattern + 0x4d]"
		script = "Type.am CRxMgrThl,uint32_t,skills,3,$result"
	strings:
		//函数第一个引用位置在CRxMgrThl的构造函数中		
		$pattern = { C7 [2] 1E 00 00 00 C7 [2] 20 00 00 00 C7 [2] 11 00 00 00 C7 [2] 2D 00 00 00 C7 [2] 1F 00 00 00 [40] 81 }
	condition:
		#pattern == 1
}


rule CRxMgrThl_end
{
	meta:
		script = "Type.print CRxMgrThl,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}