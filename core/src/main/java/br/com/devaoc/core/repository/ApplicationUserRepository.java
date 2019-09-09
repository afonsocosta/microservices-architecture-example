package br.com.devaoc.core.repository;

import br.com.devaoc.core.model.ApplicationUser;
import br.com.devaoc.core.model.Course;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface ApplicationUserRepository extends PagingAndSortingRepository<ApplicationUser, Long> {

    ApplicationUser findByUsername(String username);

}
