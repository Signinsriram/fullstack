package com.oasys.banksecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oasys.banksecurity.entity.Bank;

public interface BankRepository extends JpaRepository<Bank, Integer> {

}
