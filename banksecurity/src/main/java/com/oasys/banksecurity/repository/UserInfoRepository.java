package com.oasys.banksecurity.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oasys.banksecurity.entity.UserInfo;

public interface UserInfoRepository extends JpaRepository<UserInfo, Integer>{
Optional<UserInfo> findByusername(String username);
}
