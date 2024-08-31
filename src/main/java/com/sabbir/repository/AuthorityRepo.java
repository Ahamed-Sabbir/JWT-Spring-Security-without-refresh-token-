package com.sabbir.repository;

import com.sabbir.model.Authority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorityRepo extends JpaRepository<Authority, Integer> {
    Authority findByAuthority(String authority);
}
