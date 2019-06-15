#steamBot
经过2个多月的调试开发,终于把steamBot的主要接口都实现了。目前只提供了函数库,通过二次开发便可投入使用,本项目严格遵守Apache License V2
以下为目前已实现的API


- 接受/拒绝/取消/发起交易
- 支持二步验证的登录
- 支持运算二步验证吗
- 获取steamID SessionID
- 获取玩家游戏列表
- 获取API秘钥
- 获取玩家库存
- 获取确认页
- 确认/拒绝/取消发货交易

代码放库[有问题戳我BLOG留言,我看得见的OWO],demo已经包含在函数库内
<hr>
使用方法:
<code>
$steambot = new SteamBot();
$steambot->函数名();
</code>
<hr>
出现Empty Response/NULL的时候,通常都是因为不可以访问Steamcommunity,建议挂一个UU加速器后再运行机器人
<hr>
邮箱:gz_7gugu@outlook.com

Blog Link:www.7gugu.com