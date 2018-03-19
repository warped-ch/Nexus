/*******************************************************************************************
 
			Hash(BEGIN(Satoshi[2010]), END(Sunny[2012])) == Videlicet[2014] ++
   
 [Learn and Create] Viz. http://www.opensource.org/licenses/mit-license.php
  
*******************************************************************************************/

#include <boost/assign/list_of.hpp>

#include "core.h"
#include "unifiedtime.h"
#include "../wallet/db.h"
#include "../wallet/wallet.h"
#include "../main.h" //for pwalletmain

#include "../LLD/index.h"

using namespace std;

/** Locate the Add Coinstake Inputs Method Here for access. **/
namespace Wallet
{

	bool CWallet::AddCoinstakeInputs(Core::CTransaction& txNew)
    {
		/* Add Each Input to Transaction. */
		vector<const CWalletTx*> vInputs;
		vector<const CWalletTx*> vCoins;
		
		txNew.vout[0].nValue = 0;
		
		{
		   LOCK(cs_wallet);
		   
		   vCoins.reserve(mapWallet.size());
		   for (map<uint512, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
			   vCoins.push_back(&(*it).second);
		}
		
		random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);
		BOOST_FOREACH(const CWalletTx* pcoin, vCoins)
		{
			if (!pcoin->IsFinal() || pcoin->GetDepthInMainChain() < 60)
				continue;

			if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
				continue;

			for (unsigned int i = 0; i < pcoin->vout.size(); i++)
			{
				if (pcoin->IsSpent(i) || !IsMine(pcoin->vout[i]))
					continue;

				if (pcoin->nTime > txNew.nTime)
					continue;

				//if(txNew.vout[0].nValue > (nBalance - nReserveBalance))
				//	break;
					
				/* Stop adding Inputs if has reached Maximum Transaction Size. */
				unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
				if (nBytes >= Core::MAX_BLOCK_SIZE_GEN / 5)
					break;

				txNew.vin.push_back(Core::CTxIn(pcoin->GetHash(), i));
				vInputs.push_back(pcoin);
					
				/** Add the value to the first Output for Coinstake. **/
				txNew.vout[0].nValue += pcoin->vout[i].nValue;
			}
		}
		
		if(txNew.vin.size() == 1)
			return false;
			
		/** Set the Interest for the Coinstake Transaction. **/
		int64 nInterest;
		LLD::CIndexDB indexdb("rw");
		if(!txNew.GetCoinstakeInterest(indexdb, nInterest))
			return error("AddCoinstakeInputs() : Failed to Get Interest");
		
		txNew.vout[0].nValue += nInterest;
			
		/** Sign Each Input to Transaction. **/
		for(int nIndex = 0; nIndex < vInputs.size(); nIndex++)
		{
			if (!SignSignature(*this, *vInputs[nIndex], txNew, nIndex + 1))
				return error("AddCoinstakeInputs() : Unable to sign Coinstake Transaction Input.");

		}
		
		return true;
	}

}	

namespace Core
{
	
	/** Check the Coinstake Transaction is within the rules applied for Proof of Stake. **/
	bool CBlock::VerifyStake() const
	{
		/** A] Make Sure Coinstake Transaction is First. **/
		if (!vtx[0].IsCoinStake())
			return error("CBlock::VerifyStake() : First transaction non-coinstake %s", vtx[0].GetHash().ToString().c_str());

		/** B] Make Sure Coinstake Transaction Time is Before Block. **/
		if (vtx[0].nTime >= nTime)
			return error("CBlock::VerifyStake()() : Coinstake Timestamp to far into Future.");
			
		/** C] Check that the Coinbase / CoinstakeTimstamp is after Previous Block. **/
		if (mapBlockIndex[hashPrevBlock]->GetBlockTime() >= vtx[0].nTime)
			return error("CBlock::VerifyStake() : Coinstake Timestamp too Early.");
			
		/** D] Check Average age is above Limit if No Trust Key Seen. **/
		vector< std::vector<unsigned char> > vKeys;
		Wallet::TransactionType keyType;
		if (!Wallet::Solver(vtx[0].vout[0].scriptPubKey, keyType, vKeys))
			return error("CBlock::VerifyStake() : Failed To Solve Trust Key Script.");
			
		/** E] Ensure the Key is Public Key. No Pay Hash or Script Hash for Trust Keys. **/
		if (keyType != Wallet::TX_PUBKEY)
			return error("CBlock::VerifyStake() : Trust Key must be of Public Key Type Created from Keypool.");
			
		/** F] Check the Coinstake Time is before Unified Timestamp. **/
		if(vtx[0].nTime > (GetUnifiedTimestamp() + MAX_UNIFIED_DRIFT))
			return error("CBlock::VerifyStake() : Coinstake Transaction too far in Future.");
		
		/** Set the Public Key Integer Key from Bytes. **/
		uint576 cKey;
		cKey.SetBytes(vKeys[0]);
		
		/** Determine Trust Age if the Trust Key Exists. **/
		uint64 nCoinAge = 0, nTrustAge = 0, nBlockAge = 0;
		double nTrustWeight = 0.0, nBlockWeight = 0.0;
		if(cTrustPool.Exists(cKey))
		{
			/** Check that Transaction is not Genesis when Trust Key is Established. **/
			if(vtx[0].IsGenesis())
				return error("CBlock::VerifyStake() : Cannot Produce Genesis Transaction when Trust Key Exists.");
			
			/* Check the genesis and trust timestamps. */
			if(cTrustPool.Find(cKey).nGenesisTime > mapBlockIndex[hashPrevBlock]->GetBlockTime())
				return error("CBlock::VerifyStake() : Genesis Time cannot be after Trust Time.");
				
			nTrustAge = cTrustPool.Find(cKey).Age(mapBlockIndex[hashPrevBlock]->GetBlockTime());
			nBlockAge = cTrustPool.Find(cKey).BlockAge(mapBlockIndex[hashPrevBlock]->GetBlockTime());
			
			/** Trust Weight Reaches Maximum at 30 day Limit. **/
			nTrustWeight = min(17.5, (((16.5 * log(((2.0 * nTrustAge) / (60 * 60 * 24 * 28)) + 1.0)) / log(3))) + 1.0);
			
			/** Block Weight Reaches Maximum At Trust Key Expiration. **/
			nBlockWeight = min(20.0, (((19.0 * log(((2.0 * nBlockAge) / (TRUST_KEY_EXPIRE)) + 1.0)) / log(3))) + 1.0);
		}
		else
		{
			/** Check that Transaction is not Trust when no Genesis. **/
			if(vtx[0].IsTrust())
				return error("CBlock::VerifyStake() : Cannot Produce Trust Transaction without Genesis.");
				
			/** Check that Genesis has no Transactions. **/
			if(vtx.size() != 1)
				return error("CBlock::VerifyStake() : Cannot Include Transactions with Genesis Transaction");
				
			/** Calculate the Average Coinstake Age. **/
			LLD::CIndexDB indexdb("r");
			if(!vtx[0].GetCoinstakeAge(indexdb, nCoinAge))
			{
				return error("CBlock::VerifyStake() : Failed to Get Coinstake Age.");
			}
			
			/** Trust Weight For Genesis Transaction Reaches Maximum at 90 day Limit. **/
			nTrustWeight = min(17.5, (((16.5 * log(((2.0 * nCoinAge) / (60 * 60 * 24 * 28 * 3)) + 1.0)) / log(3))) + 1.0);
		}
		
		/** G] Check the nNonce Efficiency Proportion Requirements. **/
		double nThreshold = ((nTime - vtx[0].nTime) * 100.0) / nNonce;
		double nRequired  = ((50.0 - nTrustWeight - nBlockWeight) * MAX_STAKE_WEIGHT) / std::min((int64)MAX_STAKE_WEIGHT, vtx[0].vout[0].nValue);
		if(nThreshold < nRequired)
            return error("CBlock::VerifyStake() : Coinstake / nNonce threshold too low %f Required %f. Energy efficiency limits Reached Coin Age %" PRIu64 " | Trust Age %" PRIu64 " | Block Age %" PRIu64, nThreshold, nRequired, nCoinAge, nTrustAge, nBlockAge);
			
			
		/** H] Check the Block Hash with Weighted Hash to Target. **/
		CBigNum bnTarget;
		bnTarget.SetCompact(nBits);
		uint1024 hashTarget = bnTarget.getuint1024();
		
		if(GetHash() > hashTarget)
			return error("CBlock::VerifyStake() : Proof of Stake Hash not meeting Target.");
			
		if(GetArg("-verbose", 0) >= 2)
		{
			cTrustPool.TrustScore(cKey, nTime);
			printf("CBlock::VerifyStake() : Stake Hash  %s\n", GetHash().ToString().substr(0, 20).c_str());
			printf("CBlock::VerifyStake() : Target Hash %s\n", hashTarget.ToString().substr(0, 20).c_str());
            printf("CBlock::VerifyStake() : Coin Age %" PRIu64 " Trust Age %" PRIu64 " Block Age %" PRIu64 "\n", nCoinAge, nTrustAge, nBlockAge);
			printf("CBlock::VerifyStake() : Trust Weight %f Block Weight %f\n", nTrustWeight, nBlockWeight);
            printf("CBlock::VerifyStake() : Threshold %f Required %f Time %u nNonce %" PRIu64 "\n", nThreshold, nRequired, (unsigned int)(nTime - vtx[0].nTime), nNonce);
		}

		return true;
	}
	
	
	/** Calculate the Age of the current Coinstake. Age is determined by average time from previous transactions. **/
	bool CTransaction::GetCoinstakeAge(LLD::CIndexDB& indexdb, uint64& nAge) const
	{
		/** Output figure to show the amount of coins being staked at their interest rates. **/
		nAge = 0;
		
		/** Check that the transaction is Coinstake. **/
		if(!IsCoinStake())
			return false;
		
		/** Check the coin age of each Input. **/
		for(int nIndex = 1; nIndex < vin.size(); nIndex++)
		{
			CTransaction txPrev;
			CTxIndex txindex;
			
			/** Ignore Outputs that are not in the Main Chain. **/
			if (!txPrev.ReadFromDisk(indexdb, vin[nIndex].prevout, txindex))
				return error("GetCoinstakeAge() : Invalid Previous Transaction");

			/** Read the Previous Transaction's Block from Disk. **/
			CBlock block;
			if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
				return error("GetCoinstakeAge() : Failed To Read Block from Disk");

			/** Calculate the Age and Value of given output. **/
			int64 nCoinAge = (nTime - block.GetBlockTime());
			
			/** Compound the Total Figures. **/
			nAge += nCoinAge;
		}
		
		nAge /= (vin.size() - 1);
		
		return true;
	}
	
	
	/** Obtains the proper compounded interest from given Coin Stake Transaction. **/
	bool CTransaction::GetCoinstakeInterest(LLD::CIndexDB& indexdb, int64& nInterest) const
	{
		/** Check that the transaction is Coinstake. **/
		if(!IsCoinStake())
			return error("CTransaction::GetCoinstakeInterest() : Not Coinstake Transaction");
			
		/** Extract the Key from the Script Signature. **/
		vector< std::vector<unsigned char> > vKeys;
		Wallet::TransactionType keyType;
		if (!Wallet::Solver(vout[0].scriptPubKey, keyType, vKeys))
			return error("CTransaction::GetCoinstakeInterest() : Failed To Solve Trust Key Script.");

		/** Ensure the Key is Public Key. No Pay Hash or Script Hash for Trust Keys. **/
		if (keyType != Wallet::TX_PUBKEY)
			return error("CTransaction::GetCoinstakeInterest() : Trust Key must be of Public Key Type Created from Keypool.");
		
		/** Set the Public Key Integer Key from Bytes. **/
		uint576 cKey;
		cKey.SetBytes(vKeys[0]);
			
		/** Output figure to show the amount of coins being staked at their interest rates. **/
        int64 nTotalCoins = 0, nAverageAge = 0;
		nInterest = 0;
		
		/** Calculate the Variable Interest Rate for Given Coin Age Input. [0.5% Minimum - 3% Maximum].
			Logarithmic Variable Interest Equation = 0.03 ln((9t / 31449600) + 1) / ln(10) **/
		double nInterestRate = cTrustPool.InterestRate(cKey, nTime);
			
		/** Check the coin age of each Input. **/
		for(int nIndex = 1; nIndex < vin.size(); nIndex++)
		{
			CTransaction txPrev;
			CTxIndex txindex;
			
			/** Ignore Outputs that are not in the Main Chain. **/
			if (!txPrev.ReadFromDisk(indexdb, vin[nIndex].prevout, txindex))
				return error("CTransaction::GetCoinstakeInterest() : Invalid Previous Transaction");

			/** Read the Previous Transaction's Block from Disk. **/
			CBlock block;
			if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
				return error("CTransaction::GetCoinstakeInterest() : Failed To Read Block from Disk");
				
			/** Calculate the Age and Value of given output. **/
			int64 nCoinAge = (nTime - block.GetBlockTime());
			int64 nValue = txPrev.vout[vin[nIndex].prevout.n].nValue;
			
			/** Compound the Total Figures. **/
			nTotalCoins += nValue;
			nAverageAge += nCoinAge;
		
			/** Interest is 2% of Year's Interest of Value of Coins. Coin Age is in Seconds. **/
			nInterest += ((nValue * nInterestRate * nCoinAge) / (60 * 60 * 24 * 28 * 13));
			
		}
		
		nAverageAge /= (vin.size() - 1);
		
		if(GetArg("-verbose", 0) >= 2)
			printf("CTransaction::GetCoinstakeInterest() : Total Nexus to Stake %f Generating %f Nexus from Average Age of %u Seconds at %f %% Variable Interest\n", (double)nTotalCoins / COIN, (double)nInterest / COIN, (unsigned int)nAverageAge, nInterestRate * 100.0);
		
		return true;
	}
	
	
	/** TODO: Trust Key Reactivation
	 * 
	 * Function to Check the Current Trust Key to see if it is expired.
	 * If Key is Empty, check Trust Pool for Possible Key owned by this wallet. **/
	bool CTrustPool::HasTrustKey(unsigned int nTime)
	{
		/** First Check if the Current Key is Expired. **/
		if(!vchTrustKey.empty())
		{
			uint576 cKey;
			cKey.SetBytes(vchTrustKey);
			
			/** Handle if the Trust Pool does not have current Assigned Trust Key. **/
			if(!Exists(cKey))
			{
				vchTrustKey.clear();
				return error("CTrustPool::HasTrustKey() : Current Trust Key not in Pool.");
			}
			
			/** Handle Expired Trust Key already declared. **/
			if(mapTrustKeys[cKey].Expired(nTime))
			{
				vchTrustKey.clear();
				return error("CTrustPool::HasTrustKey() : Current Trust Key is Expired.");
			}
			
			/** Set the Interest Rate for the GUI. **/
			dInterestRate = cTrustPool.InterestRate(cKey, nTime);
		}
		else
			dInterestRate = 0.005;
		
		/** Check each Trust Key to See if we Own it if there is no Key. **/
		for(std::map<uint576, CTrustKey>::iterator i = mapTrustKeys.begin(); i != mapTrustKeys.end() && vchTrustKey.empty(); ++i)
		{
				
			/** Check the Wallet and Trust Keys in Trust Pool to see if we own any keys. **/
			Wallet::NexusAddress address;
			address.SetPubKey(i->second.vchPubKey);
			if(pwalletMain->HaveKey(address))
			{
				if(i->second.Expired(nTime))
					continue;
				
				/** Extract the Key from the Script Signature. **/
				uint576 cKey;
				cKey.SetBytes(i->second.vchPubKey);
					
				/** Assigned Extracted Key to Trust Pool. **/
				if(GetArg("-verbose", 2) >= 0)
					printf("CTrustPool::HasTrustKey() : New Trust Key Extracted %s\n", cKey.ToString().substr(0, 20).c_str());
				
				vchTrustKey = i->second.vchPubKey;
				
				/** Set the Interest Rate from Key. **/
				dInterestRate = cTrustPool.InterestRate(cKey, nTime);
				
				return true;
			}
		}
		
		//if(vchTrustKey.empty())
		//	printf("CTrustPool::HasTrustKey() : No Trust Key's in Trust Pool for Current Wallet.\n");
		
		return !(vchTrustKey.empty());
	}
	
	
	/** Check a Block's Coinstake Transaction to see if it fits Trust Key Protocol. 
	
		If Key doesn't exist Transaction must meet Genesis Protocol Requirements.
		If Key does exist it Must Meet Trust Protocol Requirements. 
		
	**/
	bool CTrustPool::Check(CBlock cBlock)
	{
		/** Lock Accepting Trust Keys to Mutex. **/
		LOCK(cs);
		
		/** Ensure the Block is for Proof of Stake Only. **/
		if(!cBlock.IsProofOfStake())
			return error("CTrustPool::check() : Cannot Accept non Coinstake Transactions.");
			
		/** Extract the Key from the Script Signature. **/
		vector< std::vector<unsigned char> > vKeys;
		Wallet::TransactionType keyType;
		if (!Wallet::Solver(cBlock.vtx[0].vout[0].scriptPubKey, keyType, vKeys))
			return error("CTrustPool::check() : Failed To Solve Trust Key Script.");

		/** Ensure the Key is Public Key. No Pay Hash or Script Hash for Trust Keys. **/
		if (keyType != Wallet::TX_PUBKEY)
			return error("CTrustPool::check() : Trust Key must be of Public Key Type Created from Keypool.");
			
		
		/** Set the Public Key Integer Key from Bytes. **/
		uint576 cKey;
		cKey.SetBytes(vKeys[0]);
			
		/** Handle Genesis Transaction Rules. Genesis is checked after Trust Key Established. **/
		if(cBlock.vtx[0].IsGenesis())
		{
			/** Don't allow multiple Genesis Coinstakes. **/
			if(mapTrustKeys.count(cKey))
				return error("CTrustPool::check() : First Transaction Must be Genesis Coinstake.");
			
			/** Create the Trust Key from Genesis Transaction Block. **/			
			CTrustKey cTrustKey(vKeys[0], cBlock.GetHash(), cBlock.vtx[0].GetHash(), cBlock.nTime);
			if(!cTrustKey.CheckGenesis(cBlock))
				return error("CTrustPool::check() : Invalid Genesis Transaction.");
			
			return true;
		}
		
		/** Handle Adding Trust Transactions. **/
		else if(cBlock.vtx[0].IsTrust())
		{
			/** No Trust Transaction without a Genesis. **/
			if(!mapTrustKeys.count(cKey))
				return error("CTrustPool::check() : Cannot Create Trust Transaction without Genesis.");
				
			/** Check that the Trust Key and Current Block match. **/
			if(mapTrustKeys[cKey].vchPubKey != vKeys[0])
				return error("CTrustPool::check() : Trust Key and Block Key Mismatch.");
				
			/** Trust Keys can only exist after the Genesis Transaction. **/
			if(!mapBlockIndex.count(mapTrustKeys[cKey].hashGenesisBlock))
				return error("CTrustKey::check() : Block Not Found.");
				
			/** Don't allow Expired Trust Keys. Check Expiration from Previous Block Timestamp. **/
			if(mapTrustKeys[cKey].Expired(mapBlockIndex[cBlock.hashPrevBlock]->GetBlockTime()))
				return error("CTrustPool::check() : Cannot Create Block for Expired Trust Key.");
				
			/** Don't allow Blocks Created Before Minimum Interval. **/
			if((cBlock.nHeight - mapBlockIndex[IsGenesis(cKey) ? mapTrustKeys[cKey].hashGenesisBlock : mapTrustKeys[cKey].hashPrevBlocks.back()]->nHeight) < TRUST_KEY_MIN_INTERVAL)
				return error("CTrustPool::check() : Trust Block Created Before Minimum Trust Key Interval.");
				
			/** Don't allow Blocks Created without First Input Previous Output hash of Trust Key Hash. 
				This Secures and Anchors the Trust Key to all Descending Trust Blocks of that Key. **/
			if(cBlock.vtx[0].vin[0].prevout.hash != mapTrustKeys[cKey].GetHash()) {
				mapTrustKeys[cKey].Print();
				
				return error("CTrustPool::check() : Trust Block Input Hash Mismatch to Trust Key Hash\n%s\n%s", cBlock.vtx[0].vin[0].prevout.hash.ToString().c_str(), mapTrustKeys[cKey].GetHash().ToString().c_str());
			}
			
			/** Read the Genesis Transaction's Block from Disk. **/
			CBlock cBlockGenesis;
			if(!cBlockGenesis.ReadFromDisk(mapBlockIndex[mapTrustKeys[cKey].hashGenesisBlock]->nFile, mapBlockIndex[mapTrustKeys[cKey].hashGenesisBlock]->nBlockPos, true))
				return error("CTrustKey::CheckGenesis() : Could not Read Previous Block.");
			
			/** Double Check the Genesis Transaction. **/
			if(!mapTrustKeys[cKey].CheckGenesis(cBlockGenesis))
				return error("CTrustPool::check() : Invalid Genesis Transaction.");
			
			return true;
		}
		
		return false;
	}
		
		
	/** Remove a Block from Trust Key. **/
	bool CTrustPool::Remove(CBlock cBlock)
	{
		/** Lock Accepting Trust Keys to Mutex. **/
		LOCK(cs);
		
		/** Extract the Key from the Script Signature. **/
		vector< std::vector<unsigned char> > vKeys;
		Wallet::TransactionType keyType;
		if (!Wallet::Solver(cBlock.vtx[0].vout[0].scriptPubKey, keyType, vKeys))
			return error("CTrustPool::Remove() : Failed To Solve Trust Key Script.");

		/** Ensure the Key is Public Key. No Pay Hash or Script Hash for Trust Keys. **/
		if (keyType != Wallet::TX_PUBKEY)
			return error("CTrustPool::Remove() : Trust Key must be of Public Key Type Created from Keypool.");
			
		/** Set the Public Key Integer Key from Bytes. **/
		uint576 cKey;
		cKey.SetBytes(vKeys[0]);
			
		/** Handle Genesis Transaction Rules. Genesis is checked after Trust Key Established. **/
		if(cBlock.vtx[0].IsGenesis())
		{
			/** Only Remove Trust Key from Map if Key Exists. **/
			if(!mapTrustKeys.count(cKey) && GetArg("-verbose", 0) >= 0)
				return error("CTrustPool::Remove() : Key %s Doesn't Exist in Trust Pool\n", cKey.ToString().substr(0, 20).c_str());
				
			/** Remove the Trust Key from the Trust Pool. **/
			mapTrustKeys.erase(cKey);
			
			if(GetArg("-verbose", 0) >= 2)
				printf("CTrustPool::Remove() : Removed Genesis Trust Key %s From Trust Pool\n", cKey.ToString().substr(0, 20).c_str());
				
			return true;
		}
		
		/** Handle Adding Trust Transactions. **/
		else if(cBlock.vtx[0].IsTrust())
		{
			/** Only Remove Trust Key from Map if Key Exists. **/
			if(!mapTrustKeys.count(cKey))
				return error("CTrustPool::Remove() : Key %s Doesn't Exist in Trust Pool\n", cKey.ToString().substr(0, 20).c_str());
				
			/** Get the Index of the Block in the Trust Key. **/
			if(mapTrustKeys[cKey].hashPrevBlocks.back() != cBlock.GetHash())
				return error("CTrustPool::Remove() : Block %s Isn't in Top. Trust Block Misconfigure...\n", cBlock.GetHash().ToString().substr(0, 20).c_str());
					
			/** Remove the Trust Key from the Container. **/
			mapTrustKeys[cKey].hashPrevBlocks.pop_back();
			printf("CTrustPool::Remove() : Removed Block %s From Trust Key\n", cBlock.GetHash().ToString().substr(0, 20).c_str());
				
			return true;
		}
		
		return false;
	}
	
	
	/** Accept a Block's Coinstake into the Trust Pool Assigning it to Specified Trust Key.  
		This Method shouldn't be called before CTrustPool::Check **/
	bool CTrustPool::Accept(CBlock cBlock, bool fInit)
	{
		/** Lock Accepting Trust Keys to Mutex. **/
		LOCK(cs);
			
		/** Extract the Key from the Script Signature. **/
		vector< std::vector<unsigned char> > vKeys;
		Wallet::TransactionType keyType;
		if (!Wallet::Solver(cBlock.vtx[0].vout[0].scriptPubKey, keyType, vKeys))
			return error("CTrustPool::accept() : Failed To Solve Trust Key Script.");

		/** Ensure the Key is Public Key. No Pay Hash or Script Hash for Trust Keys. **/
		if (keyType != Wallet::TX_PUBKEY)
			return error("CTrustPool::accept() : Trust Key must be of Public Key Type Created from Keypool.");
			
		/** Set the Public Key Integer Key from Bytes. **/
		uint576 cKey;
		cKey.SetBytes(vKeys[0]);
			
		/** Handle Genesis Transaction Rules. Genesis is checked after Trust Key Established. **/
		if(cBlock.vtx[0].IsGenesis())
		{
			/** Add the New Trust Key to the Trust Pool Memory Map. **/
			CTrustKey cTrustKey(vKeys[0], cBlock.GetHash(), cBlock.vtx[0].GetHash(), cBlock.nTime);
			mapTrustKeys[cKey] = cTrustKey;
			
			/** Dump the Trust Key To Console if not Initializing. **/
			if(!fInit && GetArg("-verbose", 0) >= 2)
				cTrustKey.Print();
			
			/** Only Debug when Not Initializing. **/
			if(GetArg("-verbose", 0) >= 1 && !fInit) {
				printf("CTrustPool::accept() : New Genesis Coinstake Transaction From Block %u\n", cBlock.nHeight);
				printf("CTrustPool::ACCEPTED %s\n", cKey.ToString().substr(0, 20).c_str());
			}
			
			return true;
		}
		
		/** Handle Adding Trust Transactions. **/
		else if(cBlock.vtx[0].IsTrust())
		{
			/** Add the new block to the Trust Key. **/
			mapTrustKeys[cKey].hashPrevBlocks.push_back(cBlock.GetHash());
			
			/** Dump the Trust Key to Console if not Initializing. **/
			if(!fInit && GetArg("-verbose", 0) >= 2)
				mapTrustKeys[cKey].Print();
			
			/** Only Debug when Not Initializing. **/
			if(!fInit && GetArg("-verbose", 0) >= 1) {
				TrustScore(cKey, mapBlockIndex[cBlock.hashPrevBlock]->GetBlockTime());
				printf("CTrustPool::ACCEPTED %s\n", cKey.ToString().substr(0, 20).c_str());
			}
			
			return true;
		}
		
		return error("CTrustPool::accept() : Missing Trust or Genesis Transaction in Block.");
	}
	
	
	/** Interest is Determined By Logarithmic Equation from Genesis Key. **/
	double CTrustPool::InterestRate(uint576 cKey, unsigned int nTime) const
	{
		/** Genesis and First Trust Block awarded 0.5% interest. **/
		if(!Exists(cKey) || IsGenesis(cKey))
			return 0.005;
			
		return min(0.03, (((0.025 * log(((9.0 * (nTime - Find(cKey).nGenesisTime)) / (60 * 60 * 24 * 28 * 13)) + 1.0)) / log(10))) + 0.005);
	}
	
	/** Break the Chain Age in Minutes into Days, Hours, and Minutes. **/
	void GetTimes(unsigned int nAge, unsigned int& nDays, unsigned int& nHours, unsigned int& nMinutes)
	{
		nDays = nAge / 1440;
		nHours = (nAge - (nDays * 1440)) / 60;
		nMinutes = nAge % 60;
	}
	
	/* Trust Scoie for Trust Keys:
		Determines how trusted a key is by score. Age of the Key is determined in combination with the Trust Score and Age. */
	uint64 CTrustPool::TrustScore(uint576 cKey, unsigned int nTime) const
	{
		/** Genesis Transactions worth Zero Trust. **/
		if(!Exists(cKey) || IsGenesis(cKey))
			return 0;
		
		/* Get the Trust Key from the Trust Pool. */
		CTrustKey cTrustKey = Find(cKey);
		
		/* The Trust Scores. */
        double nPositiveTrust = 0.0, nNegativeTrust = 0.0;
		for(int nIndex = 1; nIndex < cTrustKey.hashPrevBlocks.size(); nIndex++)
		{
			/* Calculate the Trust Time of Blocks. */
			unsigned int nTrustTime = mapBlockIndex[cTrustKey.hashPrevBlocks[nIndex]]->GetBlockTime() - mapBlockIndex[cTrustKey.hashPrevBlocks[nIndex - 1]]->GetBlockTime();
			
				
			/* Calculate Consistency Moving Average over Scope of Consistency History. */
			unsigned int nMaxTimespan = TRUST_KEY_MAX_TIMESPAN * ((GetDifficulty(mapBlockIndex[cTrustKey.hashPrevBlocks[nIndex]]->nBits, 0)) / TRUST_KEY_DIFFICULTY_THRESHOLD);
			
			
			/* Calculate the Positive Trust Time in the Key. */
			if(nTrustTime < nMaxTimespan)
				nPositiveTrust += (double)((nMaxTimespan * log(((3.0 * nTrustTime) / nMaxTimespan) + 1.0)) / log(4));
			
			
			/* Calculate the Negative Trust Time in the Key. */
			else if(nTrustTime > nMaxTimespan)
				nNegativeTrust += (double)((3.0 * nMaxTimespan * log(((3.0 * nTrustTime) / nMaxTimespan) - 2.0)) / log(4));
			
		}
		
		/* Final Computation of the Trust Score. */
		double nTrustScore = std::max(0.0, (nPositiveTrust - nNegativeTrust));
		
		
		unsigned int nDays, nHours, nMinutes;
		GetTimes(cTrustKey.Age(nTime) / 60, nDays, nHours, nMinutes);
		
		if(GetArg("-verbose", 0) >= 2)
			printf("CTrustPool::TRUST [%f %%] Score %f | Age %u Days, %u Hours, %u Minutes | Positive %f | Negative %f \n", (nTrustScore * 100.0) / cTrustKey.Age(nTime), nTrustScore,  nDays, nHours, nMinutes, nPositiveTrust, nNegativeTrust);
		
		
		return (uint64)nPositiveTrust - nNegativeTrust;
	}
	
	
	/** Should not be called until key is established in block chain. 
		Block must have been received and be part of the main chain. **/
	bool CTrustKey::CheckGenesis(CBlock cBlock) const
	{
		/** Invalid if Null. **/
		if(IsNull())
			return false;
			
		/** Trust Keys must be created from only Proof of Stake Blocks. **/
		if(!cBlock.IsProofOfStake())
			return error("CTrustKey::CheckGenesis() : Genesis Key Invalid for non Proof of Stake blocks.");
			
		/** Trust Key Timestamp must be the same as Genesis Key Block Timestamp. **/		
		if(nGenesisTime != cBlock.nTime)
			return error("CTrustKey::CheckGenesis() : Time Mismatch for Trust key to Genesis Trust Block");
			
		/** Genesis Key Transaction must match Trust Key Genesis Hash. **/
		if(cBlock.vtx[0].GetHash() != hashGenesisTx)
			return error("CTrustKey::CheckGenesis() : Genesis Key Hash Mismatch to Genesis Transaction Hash");
			
		/** Extract the Key from the Script Signature. **/
		vector< std::vector<unsigned char> > vKeys;
		Wallet::TransactionType keyType;
		if (!Wallet::Solver(cBlock.vtx[0].vout[0].scriptPubKey, keyType, vKeys))
			return error("CTrustKey::IsInvalid() : Failed To Solve Trust Key Script.");

		/** Ensure the Key is Public Key. No Pay Hash or Script Hash for Trust Keys. **/
		if (keyType != Wallet::TX_PUBKEY)
			return error("CTrustKey::CheckGenesis() : Trust Key must be of Public Key Type Created from Keypool.");
		
		/** Set the Public Key. **/
		if(vKeys[0] != vchPubKey)
			return error("CTrustKey::CheckGenesis() : Trust Key Public Key and Genesis Trust Block Public Key Mismatch\n");
		
		return true;
	}
	

	/** Key is Expired if Time between Network Previous Best Block and Trust Best Previous is Greater than Expiration Time. **/
	bool CTrustKey::Expired(unsigned int nTime) const
	{
		if(BlockAge(nTime) > TRUST_KEY_EXPIRE)
			return true;
			
		return false;
	}
	
	
	/** Key is Expired if it is Invalid or Time between Network Best Block and Best Previous is Greater than Expiration Time. **/
	uint64 CTrustKey::Age(unsigned int nTime) const 
	{ 
		/* Catch overflow attacks. */
		if(nGenesisTime > nTime)
			return 1;
	  
		return (uint64)(nTime - nGenesisTime);
	}
	
	
	/** The Age of a Key in Block age as in the Time it has been since Trust Key has produced block. **/
	uint64 CTrustKey::BlockAge(unsigned int nTime) const
	{
		/* Catch overflow attacks. Should be caught in verify stake but double check here. */
		if(nGenesisTime > nTime)
			return 1;
	    
		/** Genesis Transaction Block Age is Time to Genesis Time. **/
		if(hashPrevBlocks.empty())
			return (uint64)(nTime - nGenesisTime);
		
		if(mapBlockIndex[hashPrevBlocks.back()]->GetBlockTime() > nTime)
			return 1;
			
		/** Block Age is Time to Previous Block's Time. **/
		return (uint64)(nTime - mapBlockIndex[hashPrevBlocks.back()]->GetBlockTime());
	}
	
	
	/** Proof of Stake local CPU miner. Uses minimal resources. **/
	void StakeMinter(void* parg)
	{	
		printf("Stake Minter Started\n");
		SetThreadPriority(THREAD_PRIORITY_LOWEST);

		// Each thread has its own key and counter
		Wallet::CReserveKey reservekey(pwalletMain);

		while(!fShutdown)
		{
			/* Sleep call to keep the thread from running. */
			Sleep(10);

			/* Don't stake if the wallet is locked. */
			if (pwalletMain->IsLocked())
				continue;

			/* Don't stake if there are no available nodes. */
			if (Net::vNodes.empty() || IsInitialBlockDownload())
				continue;
			
			/* Lower Level Database Instance. */
			LLD::CIndexDB indexdb("r");
			
			/* Take a snapshot of the best block. */
			uint1024 hashBest = hashBestChain;
			
			/* Create the block(s) to work on. */
			CBlock baseBlock = CreateNewBlock(reservekey, pwalletMain, 0);
			if(baseBlock.IsNull())
                continue;
			
			/* Check the Trust Keys. */
            uint576 cKey;
			if(!cTrustPool.HasTrustKey(pindexBest->GetBlockTime()))
            {
                cKey.SetBytes(reservekey.GetReservedKey());
				baseBlock.vtx[0].vout[0].scriptPubKey << reservekey.GetReservedKey() << Wallet::OP_CHECKSIG;
            }
			else
			{
				cKey.SetBytes(cTrustPool.vchTrustKey);
				
				baseBlock.vtx[0].vout[0].scriptPubKey << cTrustPool.vchTrustKey << Wallet::OP_CHECKSIG;
				baseBlock.vtx[0].vin[0].prevout.n = 0;
				baseBlock.vtx[0].vin[0].prevout.hash = cTrustPool.Find(cKey).GetHash();
			}
			
			
            /* Determine Trust Age if the Trust Key Exists. */
			uint64 nCoinAge = 0, nTrustAge = 0, nBlockAge = 0;
			double nTrustWeight = 0.0, nBlockWeight = 0.0;
			if(cTrustPool.Exists(cKey))
			{
				nTrustAge = cTrustPool.Find(cKey).Age(pindexBest->GetBlockTime());
				nBlockAge = cTrustPool.Find(cKey).BlockAge(pindexBest->GetBlockTime());
					
				/* Trust Weight Reaches Maximum at 30 day Limit. */
				nTrustWeight = min(17.5, (((16.5 * log(((2.0 * nTrustAge) / (60 * 60 * 24 * 28)) + 1.0)) / log(3))) + 1.0);
					
				/* Block Weight Reaches Maximum At Trust Key Expiration. */
				nBlockWeight = min(20.0, (((19.0 * log(((2.0 * nBlockAge) / (TRUST_KEY_EXPIRE)) + 1.0)) / log(3))) + 1.0);
			}
			else
			{
				/* Calculate the Average Coinstake Age. */
                CTransaction txNew = baseBlock.vtx[0];
                if (!pwalletMain->AddCoinstakeInputs(txNew))
                {
                    if(GetArg("-verbose", 0) >= 2)
                        error("Stake Minter : Genesis - Failed to Add Coinstake Inputs");
                    
                    Sleep(1000);
                    
                    continue;
                }
                
				if(!txNew.GetCoinstakeAge(indexdb, nCoinAge))
				{
					if(GetArg("-verbose", 0) >= 2)
						error("Stake Minter : Genesis - Failed to Get Coinstake Age.");
                    
                    Sleep(1000);
						
					continue;
				}
					
					
				/** Trust Weight For Genesis Transaction Reaches Maximum at 90 day Limit. **/
				nTrustWeight = min(17.5, (((16.5 * log(((2.0 * nCoinAge) / (60 * 60 * 24 * 28 * 3)) + 1.0)) / log(3))) + 1.0);
			}
			
			/* Get the Total Weight. */
            unsigned int nTotalWeight = nTrustWeight + nBlockWeight;
			
			
			/* Make sure coinstake is created. */
			int i = 0;
			
			/* Copy the block pointers. */
			CBlock block[nTotalWeight];
			for(i = 0; i < nTotalWeight; i++)
			{
				block[i] = baseBlock;
				if (!pwalletMain->AddCoinstakeInputs(block[i].vtx[0]))
					break;
				
				AddTransactions(block[i].vtx, pindexBest);
				
				block[i].hashMerkleRoot   = block[i].BuildMerkleTree();
			}
			
			/* Retry if coinstake wasn't created properly. */
			if(i != nTotalWeight)
				continue;
			
			if(GetArg("-verbose", 0) >= 2)
				printf("Stake Minter : Created New Block %s\n", block[0].GetHash().ToString().substr(0, 20).c_str());
				
				
			/* Set the Reporting Variables for the Qt. */
			dTrustWeight = nTrustWeight;
			dBlockWeight = nBlockWeight;
			
			
			if(GetArg("-verbose", 0) >= 0)			
                printf("Stake Minter : Staking at Total Weight %u | Trust Weight %f | Block Weight %f | Coin Age %" PRIu64 " | Trust Age %" PRIu64 "| Block Age %" PRIu64 "\n", nTotalWeight, nTrustWeight, nBlockWeight, nCoinAge, nTrustAge, nBlockAge);
			
			bool fFound = false;
			while(!fFound)
			{
				Sleep(120);
				
				if(hashBestChain != hashBest)
				{
					if(GetArg("-verbose", 0) >= 2)
						printf("Stake Minter : New Best Block\n");
					
					break;
				}
				
				for(int i = 0; i < nTotalWeight; i++)
				{
					
					/* Update the block time for difficulty accuracy. */
					block[i].UpdateTime();
					if(block[i].nTime == block[i].vtx[0].nTime)
						continue;
						
					/* Calculate the Efficiency Threshold. */
					double nThreshold = (double)((block[i].nTime - block[i].vtx[0].nTime) * 100.0) / (block[i].nNonce + 1); //+1 to account for increment if that nNonce is chosen
					double nRequired  = ((50.0 - nTrustWeight - nBlockWeight) * MAX_STAKE_WEIGHT) / std::min((int64)MAX_STAKE_WEIGHT, block[i].vtx[0].vout[0].nValue);
						
					/* Allow the Searching For Stake block if Below the Efficiency Threshold. */
					if(nThreshold < nRequired)
						continue;
					
					block[i].nNonce ++;
						
					CBigNum hashTarget;
					hashTarget.SetCompact(block[i].nBits);
					
					if(block[i].nNonce % (unsigned int)((nTrustWeight + nBlockWeight) * 5) == 0 && GetArg("-verbose", 0) >= 3)
                        printf("Stake Minter : Below Threshold %f Required %f Incrementing nNonce %" PRIu64 "\n", nThreshold, nRequired, block[i].nNonce);
							
					if (block[i].GetHash() < hashTarget.getuint1024())
					{
						
						/* Sign the new Proof of Stake Block. */
						if(GetArg("-verbose", 0) >= 0)
							printf("Stake Minter : Found New Block Hash %s\n", block[i].GetHash().ToString().substr(0, 20).c_str());
						
						if (!block[i].SignBlock(*pwalletMain))
						{	
							if(GetArg("-verbose", 0) >= 1)
								printf("Stake Minter : Could Not Sign Proof of Stake Block.");
							
							break;
						}
						
						if(!cTrustPool.Check(block[i]))
						{
							if(GetArg("-verbose", 0) >= 1)
								error("Stake Minter : Check Trust Key Failed...");
							
							break;
						}
						
						if (!block[i].CheckBlock())
						{
							if(GetArg("-verbose", 0) >= 1)
								error("Stake Minter : Check Block Failed...");
							
							break;
						}
						
						if(GetArg("-verbose", 0) >= 1)
							block[i].print();
						
						SetThreadPriority(THREAD_PRIORITY_NORMAL);
						CheckWork(&block[i], *pwalletMain, reservekey);
						SetThreadPriority(THREAD_PRIORITY_LOWEST);
						
						fFound = true;
					}
				}
			}
		}
	}
}
