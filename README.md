# Drivermain return STATUS_UNSUCCESSFUL

Put the code in NonPagedPool and fix  
copy from https://github.com/paradoxwastaken/Poseidon  
and https://bbs.pediy.com/thread-228353.htm  
  
# 注意事项  
**全程序优化要开**  
![image](pic/微信图片_20220420165928.png)  
  
**安全检查，控制流防护关了，这样不会生成无关紧要的Call**  
![image](pic/微信图片_20220420170035.png)  
![image](pic/微信图片_20220420170646.png)  
  
  
## **生成出来的代码是这样**
**特征码搜索0xDEADC0DE6666,找到后根据偏移修复**  
![image](pic/微信图片_20220420170558.png)  
  
  
**大概是这样,频繁调用的函数可以考虑call一下,这里就没call了**
![image](pic/微信图片_20220420171222.png)

# todo
换通讯,这个通讯贼慢
