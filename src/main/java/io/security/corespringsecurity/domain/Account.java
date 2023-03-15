package io.security.corespringsecurity.domain;

import lombok.Data;
import org.hibernate.query.criteria.internal.predicate.PredicateImplementor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@Data
public class Account {
    @Id
    @GeneratedValue
    private Long id;
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}
