package br.com.devaoc.api.repository;

import br.com.devaoc.api.model.Course;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {
}
