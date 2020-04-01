rule CRxImage_start
{
	meta:
		script = "Type.as CRxImage"
		script = "Type.aanc CRxImage,CRxObject"
		script = "Type.comment CRxImage,\"图像绘制管理 type=0x21\""
	condition:
		true
}

//float size;
rule CRxImage_size
{
	meta:
		script = "$result = [@pattern + 0x8]"
		script = "Type.am CRxImage,float,size,0,$result"
	strings:
		$pattern = { 8B 82 [4] D8 98 [8] 05 [7] D3 A5 07 00 [6] D3 4D 62 10 }
	condition:
		#pattern == 1
}

rule CRxImage_end
{
	meta:
		script = "Type.print CRxImage,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}