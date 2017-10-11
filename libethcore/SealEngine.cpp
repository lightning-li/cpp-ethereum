/*
	This file is part of cpp-ethereum.

	cpp-ethereum is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	cpp-ethereum is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file SealEngine.cpp
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#include "SealEngine.h"
#include "Transaction.h"
#include <libevm/ExtVMFace.h>
using namespace std;
using namespace dev;
using namespace eth;

SealEngineRegistrar* SealEngineRegistrar::s_this = nullptr;

void NoProof::init()
{
	ETH_REGISTER_SEAL_ENGINE(NoProof);
	cout << __eth_registerSealEngineFactoryNoProof()->name() << endl;
}

void SealEngineFace::verify(Strictness _s, BlockHeader const& _bi, BlockHeader const& _parent, bytesConstRef _block) const
{
	_bi.verify(_s, _parent, _block);
}

void SealEngineFace::populateFromParent(BlockHeader& _bi, BlockHeader const& _parent) const
{
	_bi.populateFromParent(_parent);
}

void SealEngineFace::verifyTransaction(ImportRequirements::value _ir, TransactionBase const& _t, BlockHeader const& _header, u256 const&) const
{
	// EIP158ForkBlock 代表的是以太坊 Spurious Dragon 硬分叉的区块号，在此次硬分叉中加入了重放攻击保护，即 EIP155，因此当重放攻击保护启用，但是还未到
	// EIP158ForkBlock 时，抛出交易签名无效异常 
	std::cout << (_ir & ImportRequirements::TransactionSignatures) << " " << (_header.number() < chainParams().EIP158ForkBlock) << " " << _t.isReplayProtected() << endl;
	if ((_ir & ImportRequirements::TransactionSignatures) && _header.number() < chainParams().EIP158ForkBlock && _t.isReplayProtected())
		BOOST_THROW_EXCEPTION(InvalidSignature());
	
	// constantinopleForkBlock 代表的是 Metropolis 阶段的第二次硬分叉，包括账户抽象化等功能，硬分叉完成后才允许交易包含 zero signature
	if ((_ir & ImportRequirements::TransactionSignatures) && _header.number() < chainParams().constantinopleForkBlock && _t.hasZeroSignature())
		BOOST_THROW_EXCEPTION(InvalidSignature());
	
	// 当交易包含 zero signature 时，交易的 value、nonce、gasPrice 必须均为 0
	if ((_ir & ImportRequirements::TransactionBasic) &&
		_header.number() >= chainParams().constantinopleForkBlock &&
		_t.hasZeroSignature() &&
		(_t.value() != 0 || _t.gasPrice() != 0 || _t.nonce() != 0))
			BOOST_THROW_EXCEPTION(InvalidZeroSignatureTransaction() << errinfo_got((bigint)_t.gasPrice()) << errinfo_got((bigint)_t.value()) << errinfo_got((bigint)_t.nonce()));

	// homestead 硬分叉 (EIP 2)之后，交易签名中的 s 如果大于 secp256k1n/2 则视为无效，在 checkLowS 中检查
	if (_header.number() >= chainParams().homesteadForkBlock && (_ir & ImportRequirements::TransactionSignatures) && _t.hasSignature())
		_t.checkLowS();
}

SealEngineFace* SealEngineRegistrar::create(ChainOperationParams const& _params)
{
	SealEngineFace* ret = create(_params.sealEngineName);
	assert(ret && "Seal engine not found.");
	if (ret)
		ret->setChainParams(_params);
	return ret;
}

EVMSchedule const& SealEngineBase::evmSchedule(u256 const& _blockNumber) const
{
	return chainParams().scheduleForBlockNumber(_blockNumber);
}

u256 SealEngineBase::blockReward(u256 const& _blockNumber) const
{
	EVMSchedule const& schedule{evmSchedule(_blockNumber)};
	return chainParams().blockReward(schedule);
}
