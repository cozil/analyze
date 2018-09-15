rule CRxMgrThl_start
{
	meta:
		script = "log \"struct CRxMgrThl {\""
	condition:
		true
}

//230 int pkskills[3];
rule CRxMgrThl_pkskills
{
	meta:
		script = "$result = [@pattern + 0x1a]"
		script = "log \"/*{p:$result}*/    int pkskills[3];\""
	strings:
	
		//������һ������λ����CRxMgrThl�Ĺ��캯����
		//�鿴��ThlAttackMgr��ֵ�����ã������ҵ����캯��
	
		$pattern = {  C7 45 ?? 1F 00 00 00 C6 45 ?? 00 85 DB 0F 8E [4] BA 11 86 1E 00 8D BE}
	condition:
		#pattern == 1
}
 
//23c int skills[6];
rule CRxMgrThl_skills
{
	meta:
		script = "$result = [@pattern + 0x4a]"
		script = "log \"/*{p:$result}*/    int skills[6];\""
	strings:
		//������һ������λ����CRxMgrThl�Ĺ��캯����		
		$pattern = { 1E 00 00 00 [3] 20 00 00 00 [3] 11 00 00 00 [3] 2D 00 00 00 [3] 1F 00 00 00 BB 02 00 00 00 [35] 81 C6 3C 02 00 00 }
	condition:
		#pattern == 1
}


rule CRxMgrThl_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}