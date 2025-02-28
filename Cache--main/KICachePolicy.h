#pragma once //该头文件如果已经被包含过了，就不再包含

namespace KamaCache
{

template <typename Key, typename Value>
class KICachePolicy
{
public:
    virtual ~KICachePolicy() {};// 虚函数 析构函数由派生类自己实现

    // 添加缓存接口
    // = 0代表这是一个纯虚函数
    // 派生类必须实现这个虚函数 基类不提供实现
    // 基类无法实例化
    virtual void put(Key key, Value value) = 0;

    // key是传入参数  访问到的值以传出参数的形式返回 | 访问成功返回true
    virtual bool get(Key key, Value& value) = 0;
    // 如果缓存中能找到key，则直接返回value
    virtual Value get(Key key) = 0;

};

} // namespace KamaCache